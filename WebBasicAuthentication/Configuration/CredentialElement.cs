using System;
using System.Configuration;

namespace WebBasicAuthentication.Configuration
{
	public class CredentialElement : ConfigurationElement
	{
		private const string UserNameAttribute = "username";
		private const string PasswordAttribute = "password";
		private const string GroupAttribute = "group";

		/// <summary>
		/// Gets or sets the UserName.
		/// </summary>
		[ConfigurationProperty(UserNameAttribute, IsRequired = true)]
		public string UserName
		{
			get { return Convert.ToString(this[UserNameAttribute]); }
			set { this[UserNameAttribute] = value; }
		}

		/// <summary>
		/// Gets or sets the Password.
		/// </summary>
		[ConfigurationProperty(PasswordAttribute, IsRequired = true)]
		public string Password
		{
			get { return Convert.ToString(this[PasswordAttribute]); }
			set { this[PasswordAttribute] = value; }
		}

		/// <summary>
		/// Gets or sets the role name.
		/// </summary>
		[ConfigurationProperty(GroupAttribute, IsRequired = false, DefaultValue = "")]
		public string Group
		{
			get { return Convert.ToString(this[GroupAttribute]); }
			set { this[GroupAttribute] = value; }
		}
	}
}