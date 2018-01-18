namespace NetSessionEnumHarden {

    #region Usings
    using Microsoft.Win32;
    using System;
    using System.Collections.Generic;
    using System.Configuration;
    using System.Diagnostics;
    using System.Linq;
    using System.Reflection;
    using System.Runtime.InteropServices;
    using System.Security.AccessControl;
    using System.Security.Principal;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using System.Xml.Linq;
    #endregion

    /// <summary>
    /// Checks and hardens permissions on registry value:
    /// Key: HKLM\System\CurrentControlSet\Services\LanManServer\DefaultSecurity
    /// Value: SrvsvcSessionInfo
    /// If no parameters are specified, the default action is to enumerate the permissions and write them to the console and application event log.
    /// If the -u switch is specified, the permissions for Authenticiated Users is removed, and permissions for the following identities are added:
    ///  - InteractiveSid
    ///  - ServiceSid
    ///  - BatchSid
    /// If -r switch is specified, registry key is restored from the default backup registry value, "SrvsvcSessionInfoBackup".
    /// If -ro switch is specified, registry key is restored from the default backup registry value, "SrvsvcSessionInfoBackupOriginal".
    /// When -u is specified, two backups are created: "SrvsvcSessionInfoBackup" and "SrvsvcSessionInfoBackupOriginal".
    /// SrvsvcSessionInfoBackupOriginal is never overwritten. 
    /// SrvsvcSessionInfoBackup is overwritten every time it is run with -u.
    /// NOTE: Restarting the server service (or the computer) is required for the changes to go into effect.
    /// </summary>
    class Program {

        #region Enums
        private enum ReportFormat {
            XML,
            CSV
        }
        #endregion

        #region Members
        /// <summary>
        /// Used for single-instance validation to ensure only one instance of the application is running.
        /// </summary>
        private static Mutex mutex;

        /// <summary>
        /// The net session enumeration registry key name
        /// </summary>
        private static string NetSessionRegistryKey = @"System\CurrentControlSet\Services\LanManServer\DefaultSecurity";

        /// <summary>
        /// The net session enumeration registry value name
        /// </summary>
        private static string NetSessionRegistryValue = "SrvsvcSessionInfo";

        /// <summary>
        /// The net session enumeration registry value name used to make a backup copy.
        /// This value is updated every time the application is run with the -u switch.
        /// </summary>
        private static string NetSessionRegistryValueBackup = "SrvsvcSessionInfoBackup";

        /// <summary>
        /// The net session enumeration registry value name used to make a backup copy.
        /// This value is only created once and never updated.
        /// </summary>
        private static string NetSessionRegistryValueBackupOriginal = "SrvsvcSessionInfoBackupOriginal";

        /// <summary>
        /// The collection of security princpals that have permissions on the SrvsvcSessionInfo registry value.
        /// </summary>
        private static List<NetSessionSecurityPrincipal> NetSessionSecurityPrincipals { get; set; }

        private static ReportFormat OutputFormat { get; set; }

        /// <summary>
        /// The minimum required version of .NET Framework 4 (4.5.2)
        /// </summary>
        private static Version RequiredNETFrameworkVersion = new Version(4, 5, 51209);
        #endregion

        #region Constructor
        static Program() {
            NetSessionSecurityPrincipals = new List<NetSessionSecurityPrincipal>();
        }
        #endregion

        #region Methods
        /// <summary>
        /// Unhandled Exception Handler
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Event Args</param>
        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e) {
            Exception exception = e.ExceptionObject as Exception;
            EventLog.WriteEntry("Application", exception.VerboseExceptionString(), EventLogEntryType.Error);
        }

        /// <summary>
        /// Gets the installed version of .NET Framework 4
        /// </summary>
        /// .NET Framework 4
        /// 4.5.50709 4.5.0 (Windows 8.0/2012)
        /// 4.5.50938 4.5.1
        /// 4.5.51209 4.5.2 (Windows 7/Server 2008 R2) (Windows 8.0/2012)
        /// 4.5.51650 4.5.2 (Windows 8.1/Server 2012 R2)
        /// 4.6.00042 (Windows 10 RC)
        /// 4.6.01055 4.6.1 (Windows 7/Windows Server 2008 R2/Windows Server 2012 R2)
        /// 4.6.01586 4.6.1 Windows 10 1607
        /// 4.6.01586 4.6.1 Windows Server 2016
        /// <returns>The installed .NET Framework version</returns>
        private static Version GetFrameworkVersion() {

            Version netFramework4Version = null;

            using (RegistryKey net4RegistryKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full")) {
                if (net4RegistryKey != null) {
                    object net4VersionValue = net4RegistryKey.GetValue("Version");
                    if (net4VersionValue != null) {
                        Version.TryParse(net4VersionValue.ToString(), out netFramework4Version);
                    }
                }
            }

            return netFramework4Version;
        }

        /// <summary>
        /// Main entry point
        /// </summary>
        /// <param name="args"></param>
        /// <returns>0 success, 1 fail</returns>
        static int Main(string[] args) {
            #region Console settings
            Console.WindowWidth = 120;
            Console.WindowHeight = 40;
            Console.BufferHeight = 9999;
            #endregion

            AppDomain.CurrentDomain.UnhandledException += new UnhandledExceptionEventHandler(CurrentDomain_UnhandledException);
            int successReturnValue = 0;
            int failureReturnValue = 1;

            #region .NET Framework version check
            var netFramework4Version = GetFrameworkVersion();

            if ((netFramework4Version == null) || (netFramework4Version < RequiredNETFrameworkVersion)) {
                var message = string.Format("{0} requires .NET Framework {1} or higher. Version expected: {2}. Version found: {3} Application will now exit.",
                    AppDomain.CurrentDomain.FriendlyName, RequiredNETFrameworkVersion,
                    RequiredNETFrameworkVersion,
                    (netFramework4Version != null) ? netFramework4Version.ToString() : "Not found");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(message);
                Console.ResetColor();
                EventLog.WriteEntry("Application", message, EventLogEntryType.Error);
                return failureReturnValue;
            }
            #endregion

            #region Setup mutex for single-instance check
            // single-instance validation using mutex
            bool firstApplicationInstance;
            // get application GUID as defined in AssemblyInfo.cs
            string appGuid = ((GuidAttribute)Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(GuidAttribute), false).GetValue(0)).Value;
            // unique id for global mutex - Global prefix means it is global to the machine
            string mutexId = string.Format(@"Global\{{{0}}}", appGuid);
            #endregion

            using (mutex = new Mutex(initiallyOwned: false, name: mutexId, createdNew: out firstApplicationInstance)) {

                #region Check for single-instance mutex
                if (!firstApplicationInstance) {
                    var message = string.Format("Another instance of {0} is already running, application will now exit.", AppDomain.CurrentDomain.FriendlyName);
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(message);
                    Console.ResetColor();
                    EventLog.WriteEntry("Application", message, EventLogEntryType.Warning);
                    Thread.Sleep(TimeSpan.FromSeconds(5));
                    return failureReturnValue;
                }
                #endregion

                #region Set security on mutex to allow access to Everyone
                var allowEveryoneRule = new MutexAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), MutexRights.FullControl, AccessControlType.Allow);
                var securitySettings = new MutexSecurity();
                securitySettings.AddAccessRule(allowEveryoneRule);
                mutex.SetAccessControl(securitySettings);
                #endregion

                var argsList = new List<string>();
                foreach (var arg in args) {
                    argsList.Add(arg.ToLowerInvariant());
                }

                #region Output Format
                var format = ReportFormat.XML;
                int formatIndex = argsList.IndexOf("-f");
                if (formatIndex > -1) {
                    if (argsList.Count > formatIndex) {
                        if (Enum.TryParse<ReportFormat>(argsList[formatIndex + 1], true, out format)) {
                            if (!Enum.IsDefined(typeof(ReportFormat), format)) {
                                Console.WriteLine("Invalid report format specified: {0}", argsList[formatIndex + 1]);
                                return failureReturnValue;
                            }
                        }
                        else {
                            Console.WriteLine("Invalid report format specified: {0}", argsList[formatIndex + 1]);
                            return failureReturnValue;
                        }
                    }
                    else {
                        Console.WriteLine("-f specified without required parameter.");
                        return failureReturnValue;
                    }

                    OutputFormat = format;
                }
                #endregion

                #region No switches except format
                if ((argsList.Count == 0) || ((argsList.IndexOf("-f") > -1) && (argsList.Count == 2))) {
                    var message = string.Format("{0} called with no switches, permissions will only be enumerated and logged to Application event log.",
                        AppDomain.CurrentDomain.FriendlyName);
                    if (Environment.UserInteractive) {
                        Console.WriteLine(message);
                    }
                    EventLog.WriteEntry("Application", message, EventLogEntryType.Information);

                    if (!EnumerateNetSessionPermissions()) {
                        return failureReturnValue;
                    }
                    else {
                        return successReturnValue;
                    }
                }
                #endregion

                if (argsList.Any(x => string.Equals(x, "-u", StringComparison.OrdinalIgnoreCase))) {
                    #region Check for conflicting action switches
                    if (argsList.Any(x => string.Equals(x, "-r", StringComparison.OrdinalIgnoreCase)) || argsList.Any(x => string.Equals(x, "-ro", StringComparison.OrdinalIgnoreCase))) {
                        var exclusiveMessage = string.Format("{0} -u, -r, and -ro switches are mutually exclusive and may not be specified together.", AppDomain.CurrentDomain.FriendlyName);
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(exclusiveMessage);
                        Console.ResetColor();
                        EventLog.WriteEntry("Application", exclusiveMessage, EventLogEntryType.Error);
                        return failureReturnValue;
                    } 
                    #endregion

                    var message = string.Format("{0} called with -u switch, permissions will enumerated and logged to Application event log, and updated.",
                    AppDomain.CurrentDomain.FriendlyName);
                    if (Environment.UserInteractive) {
                        Console.WriteLine(message);
                    }
                    EventLog.WriteEntry("Application", message, EventLogEntryType.Information);
                    if (!UpdateNetSessionPermissions()) return failureReturnValue;
                }
                else if (argsList.Any(x => string.Equals(x, "-ro", StringComparison.OrdinalIgnoreCase))) {
                    #region Check for conflicting action switches
                    if (argsList.Any(x => string.Equals(x, "-u", StringComparison.OrdinalIgnoreCase)) || argsList.Any(x => string.Equals(x, "-r", StringComparison.OrdinalIgnoreCase))) {
                        var exclusiveMessage = string.Format("{0} -u, -r, and -ro switches are mutually exclusive and may not be specified together.", AppDomain.CurrentDomain.FriendlyName);
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(exclusiveMessage);
                        Console.ResetColor();
                        EventLog.WriteEntry("Application", exclusiveMessage, EventLogEntryType.Error);
                        return failureReturnValue;
                    }
                    #endregion

                    var message = string.Format(@"{0} called with -ro switch, original permissions will be restored from backup registry value:{1} HKLM\{2}!{3}.",
                        AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValueBackupOriginal);
                    if (Environment.UserInteractive) {
                        Console.WriteLine(message);
                    }
                    EventLog.WriteEntry("Application", message, EventLogEntryType.Information);
                    if (!RestoreNetSessionPermissions(NetSessionRegistryValueBackupOriginal)) return failureReturnValue;
                }
                else if (argsList.Any(x => string.Equals(x, "-r", StringComparison.OrdinalIgnoreCase))) {
                    #region Check for conflicting action switches
                    if (argsList.Any(x => string.Equals(x, "-u", StringComparison.OrdinalIgnoreCase)) || argsList.Any(x => string.Equals(x, "-ro", StringComparison.OrdinalIgnoreCase))) {
                        var exclusiveMessage = string.Format("{0} -u, -r, and -ro switches are mutually exclusive and may not be specified together.", AppDomain.CurrentDomain.FriendlyName);
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(exclusiveMessage);
                        Console.ResetColor();
                        EventLog.WriteEntry("Application", exclusiveMessage, EventLogEntryType.Error);
                        return failureReturnValue;
                    }
                    #endregion

                    var message = string.Format(@"{0} called with -r switch, permissions will be restored from backup registry value:{1} HKLM\{2}!{3}.",
                        AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValueBackup);
                    if (Environment.UserInteractive) {
                        Console.WriteLine(message);
                    }
                    EventLog.WriteEntry("Application", message, EventLogEntryType.Information);
                    if (!RestoreNetSessionPermissions()) return failureReturnValue;
                }
                else {
                    var message = new StringBuilder();
                    message.AppendLine("Usage: NetSessionEnumHarden.exe [-u] | [-r] | [-ro] [-f CSV | XML]");
                    message.AppendLine(" -u Update Permissions");
                    message.AppendLine(" -r Restore Permissions");
                    message.AppendLine(" -ro Restore Original Permissions");
                    message.AppendLine(" -f Specify output format (CSV or XML). Default is XML.");
                    message.AppendLine();
                    message.AppendLine(string.Format(@"Called without switches the permissions are enumerated on registry value:{0} HKLM\{1}!{2}",
                        Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValue));

                    if (argsList.Any(x => string.Equals(x, "-?", StringComparison.OrdinalIgnoreCase))) {
                        Console.WriteLine(message.ToString());
                    }
                    else {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(message.ToString());
                        Console.ResetColor();
                        EventLog.WriteEntry("Application", message.ToString(), EventLogEntryType.Error);
                        return failureReturnValue;
                    }
                }
            }

            return successReturnValue;
        }

        #region Permissions enumeration and modification methods

        /// <summary>
        /// Enumerates permisions for the SrvsvcSessionInfo registry value and records the permissions to the Application event log.
        /// Key: HKLM\System\CurrentControlSet\Services\LanManServer\DefaultSecurity
        /// Value: SrvsvcSessionInfo
        /// </summary>
        /// <returns>True if permissions were successfully enumerated and recorded to Application event log.</returns>
        /// <remarks>
        /// Well-known security identifiers in Windows operating systems 
        /// https://support.microsoft.com/en-us/kb/243330
        /// </remarks>
        private static bool EnumerateNetSessionPermissions() {
            if (Environment.UserInteractive) {
                Console.WriteLine(@"{0} {1} Enumerating permissions on registry value:{2} HKLM\{3}!{4}",
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Extensions.CurrentMethodName(),
                Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValue);
            }

            bool success = false;

            try {
                NetSessionSecurityPrincipals = new List<NetSessionSecurityPrincipal>();

                using (var lmServerDefaultSecurityRegistryKey = Registry.LocalMachine.OpenSubKey(NetSessionRegistryKey)) {
                    if (lmServerDefaultSecurityRegistryKey != null) {
                        var srvsvcSessionInfoRegistryValue = lmServerDefaultSecurityRegistryKey.GetValue(NetSessionRegistryValue);
                        if (srvsvcSessionInfoRegistryValue != null) {

                            var securityDescriptor = new CommonSecurityDescriptor(isContainer: true, isDS: false, binaryForm: (byte[])srvsvcSessionInfoRegistryValue, offset: 0);
                            if (securityDescriptor != null) {

                                foreach (CommonAce dacl in securityDescriptor.DiscretionaryAcl) {
                                    var netSessionSecurityPrincipal = new NetSessionSecurityPrincipal(dacl.SecurityIdentifier, dacl.AccessMask);
                                    if (netSessionSecurityPrincipal.IsValid()) {
                                        NetSessionSecurityPrincipals.Add(netSessionSecurityPrincipal);
                                    }

                                } // foreach (CommonAce dacl in securityDescriptor.DiscretionaryAcl) {

                                if (NetSessionSecurityPrincipals.Count > 0) {

                                    var netSessionsSecurityPrincpalsXml = GetNetSessionSecurityPrincipals();
                                    Console.WriteLine(netSessionsSecurityPrincpalsXml);

                                    EventLog.WriteEntry("Application", netSessionsSecurityPrincpalsXml, EventLogEntryType.Information);

                                    #region Sample output on a fixed system:
                                    //<ArrayOfNetSessionSecurityPrincipal>
                                    //  <!--Permissions for registry value: HKLM\System\CurrentControlSet\Services\LanManServer\DefaultSecurity!SrvsvcSessionInfo-->
                                    //  <NetSessionSecurityPrincipal>
                                    //    <SID>S-1-5-3</SID>
                                    //    <PrincipalName>BatchSid</PrincipalName>
                                    //    <AccessMask>QueryValues</AccessMask>
                                    //  </NetSessionSecurityPrincipal>
                                    //  <NetSessionSecurityPrincipal>
                                    //    <SID>S-1-5-4</SID>
                                    //    <PrincipalName>InteractiveSid</PrincipalName>
                                    //    <AccessMask>QueryValues</AccessMask>
                                    //  </NetSessionSecurityPrincipal>
                                    //  <NetSessionSecurityPrincipal>
                                    //    <SID>S-1-5-6</SID>
                                    //    <PrincipalName>ServiceSid</PrincipalName>
                                    //    <AccessMask>QueryValues</AccessMask>
                                    //  </NetSessionSecurityPrincipal>
                                    //  <NetSessionSecurityPrincipal>
                                    //    <SID>S-1-5-32-544</SID>
                                    //    <PrincipalName>BuiltinAdministratorsSid</PrincipalName>
                                    //    <AccessMask>QueryValues, SetValue, Notify, Delete, ReadPermissions, ChangePermissions, TakeOwnership</AccessMask>
                                    //  </NetSessionSecurityPrincipal>
                                    //  <NetSessionSecurityPrincipal>
                                    //    <SID>S-1-5-32-547</SID>
                                    //    <PrincipalName>BuiltinPowerUsersSid</PrincipalName>
                                    //    <AccessMask>QueryValues, SetValue, Notify, Delete, ReadPermissions, ChangePermissions, TakeOwnership</AccessMask>
                                    //  </NetSessionSecurityPrincipal>
                                    //  <NetSessionSecurityPrincipal>
                                    //    <SID>S-1-5-32-549</SID>
                                    //    <PrincipalName>BuiltinSystemOperatorsSid</PrincipalName>
                                    //    <AccessMask>QueryValues, SetValue, Notify, Delete, ReadPermissions, ChangePermissions, TakeOwnership</AccessMask>
                                    //  </NetSessionSecurityPrincipal>
                                    //</ArrayOfNetSessionSecurityPrincipal> 
                                    #endregion

                                    success = true;

                                }
                                else {
                                    // no permissions found - fail.
                                    var message = string.Format(@"{0} no permissions found on Registry value:{1} HKLM\{2}!{3}. Fail.",
                                        AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValue);
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine(message);
                                    Console.ResetColor();
                                    EventLog.WriteEntry("Application", message, EventLogEntryType.Error);
                                }
                            } // if (securityDescriptor != null) {
                            else {
                                var message = string.Format(@"{0} unable to read security descriptor on Registry value:{1} HKLM\{2}!{3} ",
                                    AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValue);
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine(message);
                                Console.ResetColor();
                                EventLog.WriteEntry("Application", message, EventLogEntryType.Error);
                            }
                        } // if (srvsvcSessionInfoRegistryValue != null) {
                        else {
                            var message = string.Format(@"{0} unable to open Registry value:{1} HKLM\{2}!{3} ",
                                AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValue);
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine(message);
                            Console.ResetColor();
                            EventLog.WriteEntry("Application", message, EventLogEntryType.Error);
                        }
                    } // if (lmServerDefaultSecurityRegistryKey != null) {
                    else {
                        var message = string.Format(@"{0} unable to open Registry key:{1} HKLM\{2} ",
                            AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey);
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(message);
                        Console.ResetColor();
                        EventLog.WriteEntry("Application", message, EventLogEntryType.Error);
                    }
                }
            }
            catch (Exception e) {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("{0} {1} Error: {2}",
                    DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Extensions.CurrentMethodName(), e.VerboseExceptionString());
                Console.ResetColor();

                success = false;
            }

            return success;
        }

        private static string GetNetSessionSecurityPrincipals() {
            if (OutputFormat == ReportFormat.XML) {
                return GetNetSessionSecurityPrincipalsXml();
            }
            else {
                return GetNetSessionSecurityPrincipalsCsv();
            }
        }

        /// <summary>
        /// Get NetSessionSecurityPrincipals as Xml string
        /// </summary>
        /// <returns>The xml string</returns>
        private static string GetNetSessionSecurityPrincipalsCsv() {
            if (NetSessionSecurityPrincipals.Count == 0) return string.Empty;
            var info = new StringBuilder();

            info.AppendFormat(NetSessionSecurityPrincipal.CSVHeader);
            foreach (var netSessionSecurityPrincipal in NetSessionSecurityPrincipals) {
                info.AppendLine(netSessionSecurityPrincipal.ToCSVString());
            }

            return info.ToString();
        }

        /// <summary>
        /// Get NetSessionSecurityPrincipals as Xml string
        /// </summary>
        /// <returns>The xml string</returns>
        private static string GetNetSessionSecurityPrincipalsXml() {

            if (NetSessionSecurityPrincipals.Count == 0) return string.Empty;

            var rootElement = new XElement("ArrayOfNetSessionSecurityPrincipal");
            rootElement.Add(new XComment(string.Format(@"Permissions for registry value: HKLM\{0}!{1}", NetSessionRegistryKey, NetSessionRegistryValue)));

            foreach (var netSessionSecurityPrincipal in NetSessionSecurityPrincipals) {
                var childElement = new XElement("NetSessionSecurityPrincipal");
                childElement.Add(new XElement("SID", netSessionSecurityPrincipal.SID ?? "NULL"));
                childElement.Add(new XElement("PrincipalName", netSessionSecurityPrincipal.PrincipalName ?? "NULL"));
                childElement.Add(new XElement("AccessMask", netSessionSecurityPrincipal.AccessMask));
                rootElement.Add(childElement);
            }

            var xDocument = new XDocument(new XDeclaration("1.0", "UTF-8", string.Empty), rootElement);
            return xDocument.ToString();

        }

        /// <summary>
        /// Restores previously saved permissions for net session  registry value.
        /// </summary>
        /// <param name="backupRegistryValue">The registry value to use as the source of the backup.</param>
        /// <returns>True if successful.</returns>
        private static bool RestoreNetSessionPermissions(string backupRegistryValue = "") {
            if (string.IsNullOrWhiteSpace(backupRegistryValue)) {
                backupRegistryValue = NetSessionRegistryValueBackup;
            }

            bool success = false;

            try {

                using (var lmServerDefaultSecurityRegistryKey = Registry.LocalMachine.OpenSubKey(name: NetSessionRegistryKey, writable: true)) {
                    if (lmServerDefaultSecurityRegistryKey != null) {

                        var srvsvcSessionInfoRegistryValue = lmServerDefaultSecurityRegistryKey.GetValue(NetSessionRegistryValue);
                        if (srvsvcSessionInfoRegistryValue != null) {

                            var srvsvcSessionInfoBackupRegistryValue = lmServerDefaultSecurityRegistryKey.GetValue(backupRegistryValue);
                            if (srvsvcSessionInfoBackupRegistryValue != null) {

                                lmServerDefaultSecurityRegistryKey.SetValue(NetSessionRegistryValue, srvsvcSessionInfoBackupRegistryValue, RegistryValueKind.Binary);
                                success = true;

                                if (Environment.UserInteractive) {
                                    var message = new StringBuilder();
                                    message.AppendLine("Permissions restored on registry value:");
                                    message.AppendLine(string.Format(@" HKLM\{0}!{1}", NetSessionRegistryKey, NetSessionRegistryValue));
                                    message.AppendLine("From backup registry value:");
                                    message.AppendLine(string.Format(@" HKLM\{0}!{1}", NetSessionRegistryKey, backupRegistryValue));

                                    EventLog.WriteEntry("Application", message.ToString(), EventLogEntryType.Error);

                                    if (Environment.UserInteractive) {
                                        Console.WriteLine(@"{0} {1}{2}{3}",
                                        DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Extensions.CurrentMethodName(),
                                        Environment.NewLine, message.ToString());
                                    }
                                }

                                EnumerateNetSessionPermissions();
                            }
                            else {
                                var message = string.Format(@"{0} unable to open Backup Registry value:{1} HKLM\{2}!{3} ",
                                    AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey, backupRegistryValue);
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine(message);
                                Console.ResetColor();
                                EventLog.WriteEntry("Application", message, EventLogEntryType.Error);
                            }
                        }
                        else {
                            var message = string.Format(@"{0} unable to open Registry value:{1} HKLM\{2}!{3} ",
                                AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValue);
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine(message);
                            Console.ResetColor();
                            EventLog.WriteEntry("Application", message, EventLogEntryType.Error);
                        }
                    }
                    else {
                        var message = string.Format(@"{0} unable to open Registry key:{1} HKLM\{2} ",
                            AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey);
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(message);
                        Console.ResetColor();
                        EventLog.WriteEntry("Application", message, EventLogEntryType.Error);
                    }
                }
            }
            catch (Exception e) {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("{0} {1} Error: {2}",
                    DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Extensions.CurrentMethodName(), e.VerboseExceptionString());
                Console.ResetColor();
                success = false;
            }

            return success;

        }

        /// <summary>
        /// Check for and remove permissions for specified SIDs and add permissions for specified SIDs on the following registry value:
        /// Key: HKLM\System\CurrentControlSet\Services\LanManServer\DefaultSecurity
        /// Value: SrvsvcSessionInfo
        /// </summary>
        private static bool UpdateNetSessionPermissions() {
            if (Environment.UserInteractive) {
                Console.WriteLine(@"{0} {1} Updating permissions on registry value:{2} HKLM\{3}!{4}",
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Extensions.CurrentMethodName(),
                Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValue);
            }

            #region Create SIDsToRemove collection
            var sidsToRemove = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (ConfigurationManager.AppSettings["SIDsToRemove"] != null) {
                var sidsToRemoveArray = ConfigurationManager.AppSettings["SIDsToRemove"].Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var sidToRemoveArrayItem in sidsToRemoveArray) {
                    var sidToRemoveArrayItemPair = sidToRemoveArrayItem.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
                    if (sidToRemoveArrayItemPair.Length == 2) {
                        if (!sidsToRemove.ContainsKey(sidToRemoveArrayItemPair[0])) {
                            sidsToRemove.Add(sidToRemoveArrayItemPair[0], sidToRemoveArrayItemPair[1]);
                        }
                    }
                }
            }

            if (sidsToRemove.Count == 0) {
                sidsToRemove.Add("S-1-5-11", "Authenticated Users");
                sidsToRemove.Add("S-1-1-0", "Everyone");
                sidsToRemove.Add("S-1-5-7", "Anonymous");
                sidsToRemove.Add("S-1-5-32-545", "Users (Built-in group)");
                sidsToRemove.Add("S-1-5-32-546", "Guests (Builtin group)");
            }

            if (Environment.UserInteractive) {
                Console.WriteLine("{0} {1} SIDsToRemove:",
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Extensions.CurrentMethodName());

                foreach (var item in sidsToRemove) {
                    Console.WriteLine(" - SID: {0} Description: {1}", item.Key, item.Value);
                }
            }
            #endregion

            #region Create SIDsToAddAccessMaskQueryValues collection
            var sidsToAddAccessMaskQueryValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (ConfigurationManager.AppSettings["SIDsToAddAccessMaskQueryValues"] != null) {
                var sidsToAddAccessMaskQueryValuesArray = ConfigurationManager.AppSettings["SIDsToAddAccessMaskQueryValues"].Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var sidsToAddAccessMaskQueryValuesArrayItem in sidsToAddAccessMaskQueryValuesArray) {
                    var sidsToAddAccessMaskQueryValuesArrayItemPair = sidsToAddAccessMaskQueryValuesArrayItem.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
                    if (sidsToAddAccessMaskQueryValuesArrayItemPair.Length == 2) {
                        if (!sidsToAddAccessMaskQueryValues.ContainsKey(sidsToAddAccessMaskQueryValuesArrayItemPair[0])) {
                            sidsToAddAccessMaskQueryValues.Add(sidsToAddAccessMaskQueryValuesArrayItemPair[0], sidsToAddAccessMaskQueryValuesArrayItemPair[1]);
                        }
                    }
                }
            }

            if (sidsToAddAccessMaskQueryValues.Count == 0) {
                sidsToAddAccessMaskQueryValues.Add("S-1-5-3", "Batch");
                sidsToAddAccessMaskQueryValues.Add("S-1-5-4", "Interactive");
                sidsToAddAccessMaskQueryValues.Add("S-1-5-6", "Service");
            }

            if (Environment.UserInteractive) {
                Console.WriteLine("{0} {1} SIDsToAddAccessMaskQueryValues:",
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Extensions.CurrentMethodName());

                foreach (var item in sidsToAddAccessMaskQueryValues) {
                    Console.WriteLine(" - SID: {0} Description: {1}", item.Key, item.Value);
                }
            }
            #endregion

            #region Create SIDsToAddAccessMaskAdministrator collection
            // QueryValues | SetValue | Notify | Delete | ReadPermissions | ChangePermissions | TakeOwnership  

            var sidsToAddAccessMaskAdministrator = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (ConfigurationManager.AppSettings["SIDsToAddAccessMaskAdministrator"] != null) {
                var sidsToAddAccessMaskAdministratorArray = ConfigurationManager.AppSettings["SIDsToAddAccessMaskAdministrator"].Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var sidsToAddAccessMaskAdministratorArrayItem in sidsToAddAccessMaskAdministratorArray) {
                    var sidsToAddAccessMaskAdministratorArrayItemPair = sidsToAddAccessMaskAdministratorArrayItem.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
                    if (sidsToAddAccessMaskAdministratorArrayItemPair.Length == 2) {
                        if (!sidsToAddAccessMaskAdministrator.ContainsKey(sidsToAddAccessMaskAdministratorArrayItemPair[0])) {
                            sidsToAddAccessMaskAdministrator.Add(sidsToAddAccessMaskAdministratorArrayItemPair[0], sidsToAddAccessMaskAdministratorArrayItemPair[1]);
                        }
                    }
                }
            }

            if (sidsToAddAccessMaskAdministrator.Count == 0) {
                sidsToAddAccessMaskAdministrator.Add("S-1-5-32-544", "Administrators (Built-in group)");
                sidsToAddAccessMaskAdministrator.Add("S-1-5-32-547", "Power Users (Built-in group)");
                sidsToAddAccessMaskAdministrator.Add("S-1-5-32-549", "Server Operators (Built-in domain controller group)");
            }

            if (Environment.UserInteractive) {
                Console.WriteLine("{0} {1} SIDsToAddAccessMaskAdministrator:",
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Extensions.CurrentMethodName());

                foreach (var item in sidsToAddAccessMaskAdministrator) {
                    Console.WriteLine(" - SID: {0} Description: {1}", item.Key, item.Value);
                }
            }
            #endregion

            bool success = false;
            bool updateRequired = false;

            try {

                #region Open registry key, check for existence of access rules for any of the SIDsToRemove collection
                using (var lmServerDefaultSecurityRegistryKey = Registry.LocalMachine.OpenSubKey(NetSessionRegistryKey)) {
                    if (lmServerDefaultSecurityRegistryKey != null) {
                        var srvsvcSessionInfoRegistryValue = lmServerDefaultSecurityRegistryKey.GetValue(NetSessionRegistryValue);
                        if (srvsvcSessionInfoRegistryValue != null) {

                            var securityDescriptor = new CommonSecurityDescriptor(isContainer: true, isDS: false, binaryForm: (byte[])srvsvcSessionInfoRegistryValue, offset: 0);
                            if (securityDescriptor != null) {

                                foreach (CommonAce dacl in securityDescriptor.DiscretionaryAcl) {
                                    if (dacl.AceFlags.HasFlag(AceFlags.Inherited)) continue;
                                    if (!dacl.AceType.HasFlag(AceType.AccessAllowed)) continue;
                                    if (sidsToRemove.Keys.Any(x => string.Equals(x, dacl.SecurityIdentifier.Value, StringComparison.OrdinalIgnoreCase))) {
                                        updateRequired = true;
                                        break;
                                    }
                                }
                            }
                            else {
                                var message = string.Format(@"{0} unable to read security descriptor on Registry value:{1} HKLM\{2}!{3} ",
                                    AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValue);
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine(message);
                                Console.ResetColor();
                                EventLog.WriteEntry("Application", message, EventLogEntryType.Error);

                            } // if (srvsvcSessionInfoRegistryValue != null) {
                        }
                        else {
                            var message = string.Format(@"{0} unable to open Registry value:{1} HKLM\{2}!{3} ",
                                AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValue);
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine(message);
                            Console.ResetColor();
                            EventLog.WriteEntry("Application", message, EventLogEntryType.Error);
                        }
                    } // if (lmServerDefaultSecurityRegistryKey != null) {
                    else {
                        var message = string.Format(@"{0} unable to open Registry key:{1} HKLM\{2} ",
                            AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey);
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(message);
                        Console.ResetColor();
                        EventLog.WriteEntry("Application", message, EventLogEntryType.Error);
                    }
                }
                #endregion

                if (updateRequired) {

                    using (var lmServerDefaultSecurityRegistryKey = Registry.LocalMachine.OpenSubKey(name: NetSessionRegistryKey, writable: true)) {
                        if (lmServerDefaultSecurityRegistryKey != null) {

                            var srvsvcSessionInfoRegistryValue = lmServerDefaultSecurityRegistryKey.GetValue(NetSessionRegistryValue);
                            if (srvsvcSessionInfoRegistryValue != null) {

                                #region Make backup copy.
                                // check for original backup.  If not exist, create it. This value is never overwritten.
                                var srvsvcSessionInfoBackupOriginalRegistryValue = lmServerDefaultSecurityRegistryKey.GetValue(NetSessionRegistryValueBackupOriginal);
                                if (srvsvcSessionInfoBackupOriginalRegistryValue == null) {
                                    lmServerDefaultSecurityRegistryKey.SetValue(NetSessionRegistryValueBackupOriginal, srvsvcSessionInfoRegistryValue, RegistryValueKind.Binary);
                                }

                                // This backup is overwritten every time update is performed.
                                lmServerDefaultSecurityRegistryKey.SetValue(NetSessionRegistryValueBackup, srvsvcSessionInfoRegistryValue, RegistryValueKind.Binary);
                                #endregion

                                var securityDescriptor = new CommonSecurityDescriptor(isContainer: true, isDS: false, binaryForm: (byte[])srvsvcSessionInfoRegistryValue, offset: 0);
                                if (securityDescriptor != null) {

                                    #region Add principals with QueryValues permission
                                    foreach (var item in sidsToAddAccessMaskQueryValues) {
                                        var accessMaskQueryValuesSID = item.Key;
                                        var accessMaskQueryValuesDescription = item.Value;
                                        bool accessMaskQueryValuesEntryRequired = true;

                                        foreach (CommonAce dacl in securityDescriptor.DiscretionaryAcl) {
                                            if (string.Equals(accessMaskQueryValuesSID, dacl.SecurityIdentifier.Value, StringComparison.OrdinalIgnoreCase) && (dacl.AccessMask == 1)) {
                                                accessMaskQueryValuesEntryRequired = false;
                                                break;
                                            }
                                        }

                                        if (accessMaskQueryValuesEntryRequired) {
                                            var messageAccessMaskQueryValuesEntryRequired = string.Format(@"{0} Registry value:{1} HKLM\{2}!{3}{4} adding access rule for: SID: {5} ({6}) AccessMask: {7}",
                                                AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValue, Environment.NewLine,
                                                accessMaskQueryValuesSID, accessMaskQueryValuesDescription, RegistryRights.QueryValues);

                                            if (Environment.UserInteractive) {
                                                Console.WriteLine(string.Format("{0} {1} {2}", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Extensions.CurrentMethodName(), messageAccessMaskQueryValuesEntryRequired));
                                            }
                                            EventLog.WriteEntry("Application", messageAccessMaskQueryValuesEntryRequired, EventLogEntryType.Information);

                                            var sidToAdd = new SecurityIdentifier(accessMaskQueryValuesSID);
                                            securityDescriptor.DiscretionaryAcl.AddAccess(AccessControlType.Allow, sidToAdd, (int)RegistryRights.QueryValues, InheritanceFlags.None, PropagationFlags.None);
                                        }
                                    }
                                    #endregion

                                    #region Add principals with Administrator permission
                                    var administratorAccessMask = RegistryRights.QueryValues
                                        | RegistryRights.SetValue
                                        | RegistryRights.Notify
                                        | RegistryRights.Delete
                                        | RegistryRights.ReadPermissions
                                        | RegistryRights.ChangePermissions
                                        | RegistryRights.TakeOwnership;

                                    foreach (var item in sidsToAddAccessMaskAdministrator) {
                                        var accessMaskAdministratorSID = item.Key;
                                        var accessMaskAdministratorDescription = item.Value;
                                        bool accessMaskAdministratorEntryRequired = true;

                                        foreach (CommonAce dacl in securityDescriptor.DiscretionaryAcl) {
                                            if (string.Equals(accessMaskAdministratorSID, dacl.SecurityIdentifier.Value, StringComparison.OrdinalIgnoreCase)
                                                && (dacl.AccessMask == (int)administratorAccessMask)) {
                                                accessMaskAdministratorEntryRequired = false;
                                                break;
                                            }
                                        }

                                        if (accessMaskAdministratorEntryRequired) {
                                            var messageAccessMaskAdministratorEntryRequired = string.Format(@"{0} Registry value:{1} HKLM\{2}!{3}{4} adding access rule for: SID: {5} ({6}) AccessMask: {7}",
                                                AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValue, Environment.NewLine,
                                                accessMaskAdministratorSID, accessMaskAdministratorDescription, RegistryRights.QueryValues);

                                            if (Environment.UserInteractive) {
                                                Console.WriteLine(string.Format("{0} {1} {2}", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Extensions.CurrentMethodName(), messageAccessMaskAdministratorEntryRequired));
                                            }
                                            EventLog.WriteEntry("Application", messageAccessMaskAdministratorEntryRequired, EventLogEntryType.Information);

                                            var sidToAdd = new SecurityIdentifier(accessMaskAdministratorSID);
                                            securityDescriptor.DiscretionaryAcl.AddAccess(AccessControlType.Allow, sidToAdd, (int)administratorAccessMask, InheritanceFlags.None, PropagationFlags.None);
                                        }
                                    }
                                    #endregion

                                    #region Remove access rules for SIDs in the SIDsToRemove collection
                                    // create separate list of DACLs
                                    var dacls = new List<CommonAce>();
                                    foreach (CommonAce dacl in securityDescriptor.DiscretionaryAcl) {
                                        dacls.Add(dacl);
                                    }

                                    foreach (var dacl in dacls) {
                                        if (dacl.AceFlags.HasFlag(AceFlags.Inherited)) continue;
                                        if (!dacl.AceType.HasFlag(AceType.AccessAllowed)) continue;
                                        if (sidsToRemove.Keys.Any(x => string.Equals(x, dacl.SecurityIdentifier.Value, StringComparison.OrdinalIgnoreCase))) {

                                            var messageSidToRemove = string.Format(@"{0} Registry value:{1} HKLM\{2}!{3}{4} removing access rule for: SID: {5} AccessMask: {6}",
                                                AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValue, Environment.NewLine,
                                                dacl.SecurityIdentifier.Value, (RegistryRights)dacl.AccessMask);

                                            if (Environment.UserInteractive) {
                                                Console.WriteLine(string.Format("{0} {1} {2}", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Extensions.CurrentMethodName(), messageSidToRemove));
                                            }
                                            EventLog.WriteEntry("Application", messageSidToRemove, EventLogEntryType.Information);

                                            securityDescriptor.DiscretionaryAcl.RemoveAccessSpecific(AccessControlType.Allow, dacl.SecurityIdentifier, dacl.AccessMask, dacl.InheritanceFlags, dacl.PropagationFlags);
                                        }
                                    }
                                    #endregion

                                    var message = new StringBuilder();
                                    message.AppendLine(string.Format("{0} Updating access rules on registry value:", AppDomain.CurrentDomain.FriendlyName));
                                    message.AppendLine(string.Format(@" HKLM\{0}!{1}", NetSessionRegistryKey, NetSessionRegistryValue));
                                    message.AppendLine("Note: The server service or computer must be restarted to go into effect.");

                                    if (Environment.UserInteractive) {
                                        Console.WriteLine(string.Format("{0} {1} {2}", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Extensions.CurrentMethodName(), message.ToString()));
                                    }
                                    EventLog.WriteEntry("Application", message.ToString(), EventLogEntryType.Information);

                                    byte[] securityDescriptorByteArray = new byte[securityDescriptor.BinaryLength];
                                    securityDescriptor.GetBinaryForm(securityDescriptorByteArray, 0);
                                    lmServerDefaultSecurityRegistryKey.SetValue(NetSessionRegistryValue, securityDescriptorByteArray, RegistryValueKind.Binary);

                                    success = true;

                                    // enumerate the permissions again to record the result
                                    EnumerateNetSessionPermissions();

                                } // if (securityDescriptor != null) {
                                else {
                                    var message = string.Format(@"{0} unable to read security descriptor on Registry value:{1} HKLM\{2}!{3} ",
                                        AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValue);
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine(message);
                                    Console.ResetColor();
                                    EventLog.WriteEntry("Application", message, EventLogEntryType.Error);

                                } // if (srvsvcSessionInfoRegistryValue != null) {
                            }
                            else {
                                var message = string.Format(@"{0} unable to open Registry value:{1} HKLM\{2}!{3} ",
                                    AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValue);
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine(message);
                                Console.ResetColor();
                                EventLog.WriteEntry("Application", message, EventLogEntryType.Error);
                            }
                        } // if (lmServerDefaultSecurityRegistryKey != null) {
                        else {
                            var message = string.Format(@"{0} unable to open Registry key:{1} HKLM\{2} ",
                                AppDomain.CurrentDomain.FriendlyName, Environment.NewLine, NetSessionRegistryKey);
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine(message);
                            Console.ResetColor();
                            EventLog.WriteEntry("Application", message, EventLogEntryType.Error);
                        }
                    }
                }
                else {
                    if (Environment.UserInteractive) {
                        Console.WriteLine(@"{0} {1} Permissions update NOT required on registry value:{2} HKLM\{3}!{4}",
                        DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Extensions.CurrentMethodName(),
                        Environment.NewLine, NetSessionRegistryKey, NetSessionRegistryValue);
                    }
                    success = true;
                }
            }
            catch (Exception e) {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("{0} {1} Error: {2}",
                    DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Extensions.CurrentMethodName(), e.VerboseExceptionString());
                Console.ResetColor();
                success = false;
            }

            return success;
        }
        #endregion

        #endregion

    }
}
