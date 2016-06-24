using System.Configuration;

namespace WebBasicAuthentication.Configuration
{
	public class BasicAuthenticationConfigurationSection : ConfigurationSection
	{
		private const string CredentialsNode = "credentials";
		private const string ExcludesNode = "excludes";
		private const string RestrictionsNode = "restrictions";

		/// <summary>
		/// Gets or sets the credentials.
		/// </summary>
		/// <value>
		/// The credentials.
		/// </value>
		[ConfigurationProperty(CredentialsNode, IsRequired = false)]
		public CredentialElementCollection Credentials
		{
			get { return (CredentialElementCollection)this[CredentialsNode]; }
			set { this[CredentialsNode] = value; }
		}

		/// <summary>
		/// Gets or sets a value indicating whether authentication module should allow redirects without issuing auth challenge.
		/// </summary>
		/// <value>
		///   <c>true</c> to allow redirects; otherwise, <c>false</c>.
		/// </value>
		[ConfigurationProperty("allowRedirects", DefaultValue = "false", IsRequired = false)]
		public bool AllowRedirects
		{
			get { return (bool)this["allowRedirects"]; }
			set { this["allowRedirects"] = value; }
		}

		/// <summary>
		/// Gets or sets a value indicating whether authentication module should allow local requests without issuing auth challenge.
		/// </summary>
		/// <value>
		///   <c>true</c> to allow redirects; otherwise, <c>false</c>.
		/// </value>
		[ConfigurationProperty("allowLocal", DefaultValue = "false", IsRequired = false)]
		public bool AllowLocal
		{
			get { return (bool)this["allowLocal"]; }
			set { this["allowLocal"] = value; }
		}

		/// <summary>
		/// Gets or sets a value of cookie encryption key.
		/// </summary>
		/// <value>
		///   <c>encryption key</c> to switch on encryption; otherwise, <c>null</c>.
		/// </value>
		[ConfigurationProperty("encryptionKey", IsRequired = false)]
		public string EncryptionKey
		{
			get { return (string)this["encryptionKey"]; }
			set { this["encryptionKey"] = value; }
		}

		/// <summary>
		/// Gets or sets the URL exclusions.
		/// </summary>
		/// <value>
		/// The URL exclusions.
		/// </value>
		[ConfigurationProperty(ExcludesNode, IsRequired = false)]
		public ExcludeElementCollection Excludes
		{
			get { return (ExcludeElementCollection)this[ExcludesNode]; }
			set { this[ExcludesNode] = value; }
		}

		/// <summary>
		/// Gets or sets additional restrictions.
		/// </summary>
		[ConfigurationProperty(RestrictionsNode, IsRequired = false)]
		public RestrictionElementCollection Restrictions
		{
			get { return (RestrictionElementCollection)this[RestrictionsNode]; }
			set { this[RestrictionsNode] = value; }
		}
	}
}