
using System.Text.RegularExpressions;

namespace WebBasicAuthentication.Entities
{
	internal class ExcludedUrl
	{
		public Regex Url { get; set; }

		public Regex Verb { get; set; }
	}
}