namespace NetSessionEnumHarden {

    #region Usings
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Security.AccessControl;
    using System.Security.Principal;
    using System.Text;
    using System.Threading.Tasks;
    #endregion

    /// <summary>
    /// Represents the principals and the permissions they have on the registry value:
    /// Key: HKLM\System\CurrentControlSet\Services\LanManServer\DefaultSecurity
    /// Value: SrvsvcSessionInfo
    /// </summary>
    public class NetSessionSecurityPrincipal {

        #region Members

        #region Static members
        public static string CSVHeader = "SID,PrincipalName,AccessMask"; 
        #endregion

        /// <summary>
        /// The permissions assigned to the security principal.
        /// </summary>
        public RegistryRights AccessMask { get; private set; }

        /// <summary>
        /// The security principal friendly name, if available. May be well-known description or DOMAIN\USERNAME or DOMAIN\GROUP.
        /// </summary>
        public string PrincipalName { get; private set; }

        /// <summary>
        /// The SecurityIdentifier string
        /// </summary>
        public string SID { get; private set; }
        #endregion

        #region Constructor
        private NetSessionSecurityPrincipal() {
            this.PrincipalName = string.Empty;
            this.SID = string.Empty;
        }

        public NetSessionSecurityPrincipal(string sid, int accessMask)
            : this(new SecurityIdentifier(sid), accessMask) {
        }

        public NetSessionSecurityPrincipal(SecurityIdentifier securityIdentifier, int accessMask) 
            : this() {

            if (securityIdentifier == null) {
                throw new ArgumentNullException("securityIdentifier");
            }

            this.SID = securityIdentifier.Value;
            this.AccessMask = (RegistryRights)accessMask;

            try {
                if (securityIdentifier != null) {
                    // Check for WellKnown identity
                    foreach (var wksid in Enum.GetValues(typeof(WellKnownSidType))) {
                        if (securityIdentifier.IsWellKnown((WellKnownSidType)wksid)) {
                            this.PrincipalName = ((WellKnownSidType)wksid).ToString();
                            break;
                        }
                    }

                    if (string.IsNullOrWhiteSpace(this.PrincipalName)) {
                        NTAccount account = securityIdentifier.Translate(typeof(NTAccount)) as NTAccount;
                        if (account != null) {
                            this.PrincipalName = account.Value.Trim();
                        }
                    }

                    if (string.IsNullOrWhiteSpace(this.PrincipalName)) {
                        this.PrincipalName = "UNKNOWN";
                    }
                }
            }
            catch { }
        }
        #endregion

        #region Methods

        public bool IsValid() {

            var isValid = false;

            char accessMaskFirstDigit = this.AccessMask.ToString()[0];
            isValid = !string.IsNullOrWhiteSpace(this.SID)
             && !string.IsNullOrWhiteSpace(this.PrincipalName)
             && (!char.IsDigit(accessMaskFirstDigit) && (accessMaskFirstDigit != '-'));

            return isValid;
        }

        public string ToCSVString() {
            var info = new StringBuilder();

            info.AppendFormat("\"{0}\",", this.SID ?? "NULL");
            info.AppendFormat("\"{0}\",", this.PrincipalName ?? "NULL");
            info.AppendFormat("\"{0}\"", this.AccessMask);

            return info.ToString();
        }

        [DebuggerStepThroughAttribute]
        public override string ToString() {
            var info = new StringBuilder();

            info.AppendFormat("SID: {0}; ", this.SID ?? "NULL");
            info.AppendFormat("PrincipalName: {0}; ", this.PrincipalName ?? "NULL");
            info.AppendFormat("AccessMask: {0}; ", this.AccessMask);

            return info.ToString();
        }
        #endregion

    }
}
