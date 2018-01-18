namespace NetSessionEnumHarden {

    #region Usings
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Runtime.CompilerServices;
    using System.Text;
    using System.Threading.Tasks;
    #endregion

    internal static class Extensions {

        /// <summary>
        /// Gets the name of the current method on the stack
        /// </summary>
        /// <returns>The method name</returns>
        /// <remarks>Not an extension, placed here for convenience</remarks>
        [DebuggerStepThroughAttribute]
        [MethodImpl(MethodImplOptions.NoOptimization)]
        public static string CurrentMethodName() {
            var frame = new StackFrame(1);
            var method = frame.GetMethod();
            var type = method.DeclaringType;
            var name = method.Name;

            return type + "::" + name + "(): ";
        }

        /// <summary>
        /// Gets a newline-formatted string for a collection
        /// </summary>
        /// <typeparam name="T">The collection type</typeparam>
        /// <param name="list">The collection</param>
        /// <returns>The newline-formatted string</returns>
        [DebuggerStepThroughAttribute]
        public static string ToFormattedString<T>(this IEnumerable<T> list) {
            if (list == null) return string.Empty;
            return string.Join(Environment.NewLine, list);
        }

        /// <summary>
        /// Stack trace, target site, and error message of outer and inner exception, formatted with newlines
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="exception"></param>
        /// <returns></returns>
        [DebuggerStepThroughAttribute]
        public static string VerboseExceptionString<T>(this T exception) where T : Exception {
            var exceptionString = new StringBuilder();

            exceptionString.AppendLine(string.Format(" Exception: {0} Message: {1}", exception.GetType().Name, exception.Message != null ? exception.Message : "NULL"));
            exceptionString.AppendLine(string.Format(" StackTrace: {0}", exception.StackTrace != null ? exception.StackTrace : "NULL"));
            exceptionString.AppendLine(string.Format(" TargetSite: {0}", exception.TargetSite != null ? exception.TargetSite.ToString() : "NULL"));

            if (exception.InnerException != null) {
                exceptionString.AppendLine();
                exceptionString.AppendLine("Inner Exception:");
                exceptionString.AppendLine(exception.InnerException.VerboseExceptionString());
            }

            return exceptionString.ToString();
        }

    }
}
