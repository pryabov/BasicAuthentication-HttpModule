using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace WebBasicAuthentication.Utils
{
	// https://msdn.microsoft.com/en-us/library/system.security.cryptography.aescryptoserviceprovider(v=vs.110).aspx
	// http://www.codeproject.com/Articles/769741/Csharp-AES-bits-Encryption-Library-with-Salt
	internal class AesEncryption
	{
		private const int SaltSize = 8;

		internal static string Encrypt(string plainText, string password)
		{
			// Check arguments.
			Debug.Assert(!string.IsNullOrEmpty(plainText));
			Debug.Assert(!string.IsNullOrEmpty(password));

			string cipherText;

			byte[] saltBytes = GetRandomBytes();

			byte[] passwordBytes = GetBytes(password);
			passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

			// Create an AesCryptoServiceProvider object
			// with the specified key and IV.
			using (RijndaelManaged aesAlg = new RijndaelManaged())
			{
				aesAlg.KeySize = 256;
				aesAlg.BlockSize = 128;

				Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
				aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
				aesAlg.IV = key.GetBytes(aesAlg.BlockSize / 8);

				aesAlg.Mode = CipherMode.CBC;

				// Create a decrytor to perform the stream transform.
				ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

				// Create the streams used for encryption.
				byte[] encryptedBytes;
				// Create the streams used for encryption.
				using (MemoryStream msEncrypt = new MemoryStream())
				{
					using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
					{
						using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
						{

							//Write all data to the stream.
							swEncrypt.Write(plainText);
						}
						encryptedBytes = msEncrypt.ToArray();
					}
				}

				cipherText = Convert.ToBase64String(encryptedBytes.Concat(saltBytes).ToArray());
			}

			// Return the encrypted bytes from the memory stream.
			return cipherText;
		}

		internal static string Decrypt(string cipherText, string password)
		{
			// Check arguments.
			Debug.Assert(!string.IsNullOrEmpty(cipherText));
			Debug.Assert(!string.IsNullOrEmpty(password));

			byte[] passwordBytes = GetBytes(password);
			passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

			// Declare the string used to hold
			// the decrypted text.
			string plaintext;

			byte[] cipherBytes = Convert.FromBase64String(cipherText);

			byte[] saltBytes = GetSubArray(cipherBytes, cipherBytes.Length - SaltSize, SaltSize);
			cipherBytes = GetSubArray(cipherBytes, 0, cipherBytes.Length - SaltSize);

			// Create an AesCryptoServiceProvider object
			// with the specified key and IV.
			using (RijndaelManaged aesAlg = new RijndaelManaged())
			{
				aesAlg.KeySize = 256;
				aesAlg.BlockSize = 128;

				Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
				aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
				aesAlg.IV = key.GetBytes(aesAlg.BlockSize / 8);

				aesAlg.Mode = CipherMode.CBC;


				// Create a decrytor to perform the stream transform.
				ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

				// Create the streams used for decryption.
				using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
				{
					using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
					{
						using (StreamReader srDecrypt = new StreamReader(csDecrypt))
						{
							// Read the decrypted bytes from the decrypting stream
							// and place them in a string.
							plaintext = srDecrypt.ReadToEnd();
						}
					}
				}
			}

			return plaintext;
		}

		static byte[] GetBytes(string str)
		{
			byte[] bytes = new byte[str.Length * sizeof(char)];
			Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
			return bytes;
		}

		static string GetString(byte[] bytes)
		{
			char[] chars = new char[bytes.Length / sizeof(char)];
			Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
			return new string(chars);
		}

		public static byte[] GetRandomBytes(int length = SaltSize)
		{
			byte[] randomBytes = new byte[length];
			RandomNumberGenerator.Create().GetBytes(randomBytes);
			return randomBytes;
		}

		public static byte[] GetSubArray(byte[] data, int index, int length)
		{
			byte[] result = new byte[length];
			Array.Copy(data, index, result, 0, length);
			return result;
		}
	}
}