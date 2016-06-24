using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace WebBasicAuthentication.Entities
{
	internal  class GroupRestriction
	{
		public Regex Url { get; set; }

		public Regex Verb { get; set; }

		public List<string> Groups { get; set; }

		public GroupRestriction()
		{
			Groups = new List<string>();
		}
	}
}