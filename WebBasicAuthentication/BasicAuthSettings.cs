using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text.RegularExpressions;
using WebBasicAuthentication.Configuration;
using WebBasicAuthentication.Entities;

namespace WebBasicAuthentication
{
	internal class BasicAuthSettings
	{
		/// <summary>
		/// Indicates whether redirects are allowed without authentication.
		/// </summary>
		public bool AllowRedirects { get; protected set; }

		/// <summary>
		/// Indicates whether local requests are allowed without authentication.
		/// </summary>
		public bool AllowLocal { get; protected set; }

		/// <summary>
		/// Key to encrypt resulted cookie
		/// </summary>
		public string EncryptionKey { get; protected set; }

		/// <summary>
		/// Exclude configuration - request URL is matched to Url and request method is matched to the Verb.
		/// </summary>
		public IList<ExcludedUrl> Excludes { get; protected set; }

		/// <summary>
		/// Restrictions configuration - request URL is matched to Url request method is matched to the Verb and allowed groups in Groups property.
		/// </summary>
		public IList<GroupRestriction> GroupRestrictions { get; protected set; }

		/// <summary>
		/// The credentials that are allowed to access the site.
		/// </summary>
		public IDictionary<string, BasicAuthUser> ActiveUsers { get; protected set; }

		/// <summary>
		/// Regular expression that matches any given string.
		/// </summary>
		private static readonly Regex AllowAnyRegex = new Regex(".*", RegexOptions.Compiled);

		public BasicAuthSettings()
		{
			System.Configuration.Configuration config = System.Web.Configuration.WebConfigurationManager.OpenWebConfiguration("~/web.config");
			BasicAuthenticationConfigurationSection basicAuthSection = TraverseConfigSections<BasicAuthenticationConfigurationSection>(config.RootSectionGroup);

			if (basicAuthSection == null)
			{
				System.Diagnostics.Debug.WriteLine("BasicAuthenticationModule not started - Configuration not found. Make sure that BasicAuthenticationConfigurationSection section is defined.");
				return;
			}

			AllowRedirects = basicAuthSection.AllowRedirects;
			AllowLocal = basicAuthSection.AllowLocal;
			EncryptionKey = basicAuthSection.EncryptionKey;

			InitCredentials(basicAuthSection);
			InitExcludes(basicAuthSection);
			InitRestrictions(basicAuthSection);
		}

		private static T TraverseConfigSections<T>(ConfigurationSectionGroup group) where T : ConfigurationSection
		{
			foreach (ConfigurationSection section in group.Sections)
			{
				if (Type.GetType(section.SectionInformation.Type, false) == typeof(T))
				{
					return (T)section;
				}
			}

			foreach (ConfigurationSectionGroup g in group.SectionGroups)
			{
				T section = TraverseConfigSections<T>(g);
				if (section != null)
				{
					return section;
				}
			}

			return null;
		}

		#region Configurations Initialization

		private void InitCredentials(BasicAuthenticationConfigurationSection basicAuth)
		{
			ActiveUsers = new Dictionary<string, BasicAuthUser>();

			for (int i = 0; i < basicAuth.Credentials.Count; i++)
			{
				CredentialElement credential = basicAuth.Credentials[i];
				ActiveUsers.Add(credential.UserName, new BasicAuthUser
				{
					UserName = credential.UserName,
					Password = credential.Password,
					Group = credential.Group
				});
			}
		}

		private void InitExcludes(BasicAuthenticationConfigurationSection basicAuth)
		{
			Excludes = new List<ExcludedUrl>();

			for (int i = 0; i < basicAuth.Excludes.Count; i++)
			{
				ExcludedUrl addedExcludedUrl = new ExcludedUrl();

				string excludeUrl = basicAuth.Excludes[i].Url;
				string excludeVerb = basicAuth.Excludes[i].Verb;

				addedExcludedUrl.Url =
					string.IsNullOrEmpty(excludeUrl)
					? AllowAnyRegex
					: new Regex(excludeUrl, RegexOptions.Compiled | RegexOptions.IgnoreCase);

				addedExcludedUrl.Verb =
					string.IsNullOrEmpty(excludeVerb)
					? AllowAnyRegex
					: new Regex(excludeVerb, RegexOptions.Compiled | RegexOptions.IgnoreCase);

				Excludes.Add(addedExcludedUrl);
			}
		}

		private void InitRestrictions(BasicAuthenticationConfigurationSection basicAuth)
		{
			GroupRestrictions = new List<GroupRestriction>();

			for (int i = 0; i < basicAuth.Restrictions.Count; i++)
			{
				GroupRestriction groupRestriction = new GroupRestriction();

				string restrictionUrl = basicAuth.Restrictions[i].Url;
				string restrictionVerb = basicAuth.Restrictions[i].Verb;
				string restrictionGroups = basicAuth.Restrictions[i].Groups;

				groupRestriction.Url =
					string.IsNullOrEmpty(restrictionUrl)
					? AllowAnyRegex
					: new Regex(restrictionUrl, RegexOptions.Compiled | RegexOptions.IgnoreCase);

				groupRestriction.Verb =
					string.IsNullOrEmpty(restrictionVerb)
					? AllowAnyRegex
					: new Regex(restrictionVerb, RegexOptions.Compiled | RegexOptions.IgnoreCase);

				if (!string.IsNullOrEmpty(restrictionGroups))
				{
					List<string> groups = basicAuth.Restrictions[i]
						.Groups.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
						.Select(item => item.ToLowerInvariant()).ToList();
					groupRestriction.Groups.AddRange(groups);
				}

				GroupRestrictions.Add(groupRestriction);
			}
		}

		#endregion Configurations Initialization
	}
}