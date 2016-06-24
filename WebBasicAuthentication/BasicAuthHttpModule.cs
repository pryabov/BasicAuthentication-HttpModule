using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;
using WebBasicAuthentication.Entities;
using WebBasicAuthentication.Utils;

namespace WebBasicAuthentication
{
	/// <summary>
	/// This module performs basic authentication.
	/// For details on basic authentication see RFC 2617.
	/// Based on the work by Mike Volodarsky (www.iis.net/learn/develop/runtime-extensibility/developing-a-module-using-net)
	///
	/// The basic operational flow is:
	///
	/// On AuthenticateRequest:
	///     extract the basic authentication credentials
	///     verify the credentials
	///     if successful, create and send authentication cookie
	///
	/// On SendResponseHeaders:
	///     if there is no authentication cookie in request, clear response, add unauthorized status code (401) and
	///     add the basic authentication challenge to trigger basic authentication.
	/// </summary>
	public class BasicAuthenticationModule : IHttpModule
	{
		/// <summary>
		/// HTTP1.1 Authorization header
		/// </summary> 
		public const string HttpAuthorizationHeader = "Authorization";

		/// <summary>
		/// HTTP1.1 Basic Challenge Scheme Name
		/// </summary>
		public const string HttpBasicSchemeName = "Basic"; // 

		/// <summary>
		/// HTTP1.1 Credential username and password separator
		/// </summary>
		public const char HttpCredentialSeparator = ':';

		/// <summary>
		/// HTTP1.1 Not authorized response status code
		/// </summary>
		public const int HttpNotAuthorizedStatusCode = 401;

		/// <summary>
		/// HTTP1.1 Basic Challenge Scheme Name
		/// </summary>
		public const string HttpWwwAuthenticateHeader = "WWW-Authenticate";

		/// <summary>
		/// The name of cookie that is sent to client
		/// </summary>
		public const string AuthenticationCookieName = "BasicAuthentication";

		/// <summary>
		/// HTTP.1.1 Basic Challenge Realm
		/// </summary>
		public const string Realm = "demo";

		/// <summary>
		/// Dictionary that caches whether basic authentication challenge should be sent. Key is request URL + request method, value indicates whether
		/// challenge should be sent.
		/// </summary>
		private static readonly IDictionary<string, bool> ShouldChallengeCache = new Dictionary<string, bool>();

		/// <summary>
		/// Cached value for url, verb and group combination
		/// </summary>
		private static readonly IDictionary<string, bool> IsAllowedUrlforGroupCache = new Dictionary<string, bool>();


		private BasicAuthSettings _settings;

		public void AuthenticateUser(object source, EventArgs e)
		{
			HttpContext context = ((HttpApplication)source).Context;

			string authorizationHeader = context.Request.Headers[HttpAuthorizationHeader];

			// Extract the basic authentication credentials from the request
			string userName = null;
			string password = null;
			if (!ExtractBasicCredentials(authorizationHeader, ref userName, ref password))
			{
				return;
			}

			// Validate the user credentials
			BasicAuthUser authUser = ValidateCredentials(userName, password);
			if (authUser == null)
			{
				return;
			}

			string cookieValue = authUser.Group;
			if (!string.IsNullOrEmpty(_settings.EncryptionKey))
			{
				cookieValue = AesEncryption.Encrypt(authUser.Group, _settings.EncryptionKey);
			}
			// check whether cookie is set and send it to client if needed
			HttpCookie authCookie = new HttpCookie(AuthenticationCookieName, cookieValue) { Expires = DateTime.Now.AddHours(1) };
			context.Response.Cookies.Add(authCookie);
		}

		public void IssueAuthenticationChallenge(object source, EventArgs e)
		{
			HttpContext context = ((HttpApplication)source).Context;

			if (_settings.AllowLocal && context.Request.IsLocal)
			{
				return;
			}

			if (_settings.AllowRedirects && IsRedirect(context.Response.StatusCode))
			{
				return;
			}

			// Get current authentication cookie
			HttpCookie authCookie =
				context.Response.Cookies.Get(AuthenticationCookieName)
				?? context.Request.Cookies.Get(AuthenticationCookieName);

			if (ShouldChallenge(context))
			{
				string cookieValue = null;
				if (authCookie != null)
				{
					cookieValue = authCookie.Value;
					if (!string.IsNullOrEmpty(_settings.EncryptionKey))
					{
						try
						{
							cookieValue = AesEncryption.Decrypt(cookieValue, _settings.EncryptionKey);
						}
						catch
						{
							cookieValue = null;
						}
					}
				}

				if (cookieValue == null || !IsGroupAllowed(context, cookieValue))
				{
					context.Response.Clear();
					context.Response.StatusCode = HttpNotAuthorizedStatusCode;
					context.Response.AddHeader(HttpWwwAuthenticateHeader, "Basic realm =\"" + Realm + "\"");
				}
			}
		}

		private bool IsGroupAllowed(HttpContext context, string group)
		{
			group = group?.ToLowerInvariant();

			// first check cache
			string key = string.Concat(context.Request.Path, context.Request.HttpMethod, group);
			if (IsAllowedUrlforGroupCache.ContainsKey(key))
			{
				return IsAllowedUrlforGroupCache[key];
			}

			// if value is not found in cache check restrictions rules and found if it allowed
			if (_settings.GroupRestrictions.Any(groupRestriction =>
				groupRestriction.Url.IsMatch(context.Request.Path)
				&& groupRestriction.Verb.IsMatch(context.Request.HttpMethod)
				&& groupRestriction.Groups.Contains(@group)))
			{
				IsAllowedUrlforGroupCache[key] = true;
				return true;
			}

			// if value is not found in cache check restrictions rules and found if it not allowed
			if (_settings.GroupRestrictions.Any(groupRestriction =>
				groupRestriction.Url.IsMatch(context.Request.Path)
				&& groupRestriction.Verb.IsMatch(context.Request.HttpMethod)
				&& !groupRestriction.Groups.Contains(@group)))
			{
				IsAllowedUrlforGroupCache[key] = false;
				return false;
			}

			// if rule not mentioned then think about it like allowed
			IsAllowedUrlforGroupCache[key] = true;
			return true;
		}

		/// <summary>
		/// Returns true if authentication challenge should be sent to client based on configured exclude rules
		/// </summary>
		private bool ShouldChallenge(HttpContext context)
		{
			// first check cache
			string key = string.Concat(context.Request.Path, context.Request.HttpMethod);
			if (ShouldChallengeCache.ContainsKey(key))
			{
				return ShouldChallengeCache[key];
			}

			// if value is not found in cache check exclude rules
			if (_settings.Excludes.Any(excludedUrl =>
				excludedUrl.Url.IsMatch(context.Request.Path)
				&& excludedUrl.Verb.IsMatch(context.Request.HttpMethod)))
			{
				ShouldChallengeCache[key] = false;

				return false;
			}

			ShouldChallengeCache[key] = true;
			return true;
		}

		private static bool IsRedirect(int httpStatusCode)
		{
			return new[]
			{
				HttpStatusCode.MovedPermanently,
				HttpStatusCode.Redirect,
				HttpStatusCode.TemporaryRedirect
			}.Any(c => (int)c == httpStatusCode);
		}

		private BasicAuthUser ValidateCredentials(string userName, string password)
		{
			if (_settings.ActiveUsers.ContainsKey(userName) && _settings.ActiveUsers[userName].Password == password)
			{
				return _settings.ActiveUsers[userName];
			}

			return null;
		}

		protected virtual bool ExtractBasicCredentials(string authorizationHeader, ref string username, ref string password)
		{
			if (string.IsNullOrEmpty(authorizationHeader))
			{
				return false;
			}

			string verifiedAuthorizationHeader = authorizationHeader.Trim();
			if (verifiedAuthorizationHeader.IndexOf(HttpBasicSchemeName, StringComparison.InvariantCultureIgnoreCase) != 0)
			{
				return false;
			}

			// get the credential payload
			verifiedAuthorizationHeader = verifiedAuthorizationHeader.Substring(HttpBasicSchemeName.Length, verifiedAuthorizationHeader.Length - HttpBasicSchemeName.Length).Trim();
			// decode the base 64 encoded credential payload
			byte[] credentialBase64DecodedArray = Convert.FromBase64String(verifiedAuthorizationHeader);
			string decodedAuthorizationHeader = Encoding.UTF8.GetString(credentialBase64DecodedArray, 0, credentialBase64DecodedArray.Length);

			// get the username, password, and realm
			int separatorPosition = decodedAuthorizationHeader.IndexOf(HttpCredentialSeparator);

			if (separatorPosition <= 0)
			{
				return false;
			}

			username = decodedAuthorizationHeader.Substring(0, separatorPosition).Trim();
			password = decodedAuthorizationHeader.Substring(separatorPosition + 1, (decodedAuthorizationHeader.Length - separatorPosition - 1)).Trim();

			if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
			{
				return false;
			}

			return true;
		}

		public void Init(HttpApplication context)
		{
			_settings = new BasicAuthSettings();

			// Subscribe to the authenticate event to perform the authentication.
			context.AuthenticateRequest += AuthenticateUser;

			// Subscribe to the EndRequest event to issue the authentication challenge if necessary.
			context.EndRequest += IssueAuthenticationChallenge;
		}

		public void Dispose()
		{
			// Do nothing here
		}
	}
}
