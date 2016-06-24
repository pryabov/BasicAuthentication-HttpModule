using System;
using System.Configuration;

namespace WebBasicAuthentication.Configuration
{
	public class RestrictionElement : ConfigurationElement
	{
		private const string UrlAttribute = "url";
		private const string VerbAttribute = "verb";
		private const string GroupsAttribute = "groups";

		/// <summary>
		/// Gets or sets the url to exclude.
		/// </summary>
		[ConfigurationProperty(UrlAttribute, IsRequired = false, IsKey = false)]
		public string Url
		{
			get { return Convert.ToString(this[UrlAttribute]); }
			set { this[UrlAttribute] = value; }
		}

		/// <summary>
		/// Gets or sets the verb to exclude.
		/// </summary>
		[ConfigurationProperty(VerbAttribute, IsRequired = false, IsKey = false)]
		public string Verb
		{
			get { return Convert.ToString(this[VerbAttribute]); }
			set { this[VerbAttribute] = value; }
		}

		/// <summary>
		/// Gets or sets the verb to exclude.
		/// </summary>
		[ConfigurationProperty(GroupsAttribute, IsRequired = false, IsKey = false)]
		public string Groups
		{
			get { return Convert.ToString(this[GroupsAttribute]); }
			set { this[GroupsAttribute] = value; }
		}

		public override string ToString()
		{
			return string.Concat(Url, '_', Verb);
		}
	}
}