/*
 MIT License

Copyright (c) 2023 RYW

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.Serialization.Formatters.Binary;
using System;

	public class SaveFolder{
		public string header = "";
		public Dictionary<string,SaveDoc> docList = new Dictionary<string,SaveDoc>();

		public SaveDoc GetDoc(string docheader){
			if(docList.ContainsKey(docheader)){
				return docList[docheader];
			}
			return null;
		}

		public string SerializeFolder(){

			StreamEncapsulator encapsulator = new StreamEncapsulator();

			Dictionary<string,string> rawData = new Dictionary<string,string>();

			foreach(KeyValuePair<string,SaveDoc> kvp in docList){
				rawData.Add(kvp.Key,kvp.Value.SerializeDoc());
			}

			Dictionary<string,string> folderData = new Dictionary<string,string>();

			string _folders = encapsulator.LoadData(rawData,"/%#/");
			folderData.Add("header",header);
			folderData.Add("folders",_folders);

			return encapsulator.LoadData(folderData,"/%/");
		}

		public void DeSerializeSave(string folderdata){
			StreamEncapsulator encapsulator = new StreamEncapsulator();
			Dictionary<string,string> unpackedfData = encapsulator.UnloadData(folderdata,"/%/");
			header = unpackedfData["header"];
			Dictionary<string,string> rawFolderData = encapsulator.UnloadData(unpackedfData["folders"],"/%#/");
			foreach(KeyValuePair<string,string> kvp in rawFolderData){
				SaveDoc sv = new SaveDoc();
				sv.DeSerializeSave(kvp.Value);
				docList.Add(kvp.Key,sv);
			}
		}

		public SaveDoc CreateDoc(string docName){
			if(docList.ContainsKey(docName)) return docList[docName];
			SaveDoc sv = new SaveDoc();
			sv.header = docName;
			docList.Add(sv.header,sv);
			return sv;
		}
	}

	public class SaveDoc{
		public string header = "";
		public Dictionary<string,string> data = new Dictionary<string,string>();

		public string SerializeDoc(){
			if(data.ContainsKey("header")==true){
				data["header"] = header;
			}
			else{
				data.Add("header",header);
			}

			StreamEncapsulator encapsulator = new StreamEncapsulator();
			return encapsulator.LoadData(data,"/%###/");
		}

		public void DeSerializeSave(string input_data){
			StreamEncapsulator encapsulator = new StreamEncapsulator();
			data = encapsulator.UnloadData(input_data,"/%###/");
			header = data["header"];
		}
	}

	public class DataProcessor {

		public string datapath = "";
		public string filepath = "";

		public Dictionary<string,SaveFolder> saveFolderLib = new Dictionary<string,SaveFolder>();

		RSACryptoServiceProvider rsa;

		public string password = "";

		//note: boolean is used to determine if you should get or set rsa key store
		public bool Init(string path,string key){
			datapath = path;
			filepath = path;

			#if UNITY_ANDROID
			datapath = Application.persistentDataPath;
			//print (Application.persistentDataPath);
			#endif
			if(System.IO.File.Exists(datapath+"/"+filepath)){
				GetKeyContainer(key);
				Load();
				return true;
			}else{
				SetKeyContainer(key);
			}

			//Debug.Log("full path: "+datapath+"/"+filepath);
			return false; //there is no file that exists
		}

		public void SetKeyContainer(string keyContainer){
			CspParameters cp = new CspParameters();  
			cp.KeyContainerName = keyContainer;  

			// Create a new instance of RSACryptoServiceProvider that accesses  
			// the key container MyKeyContainerName.  
			rsa = new RSACryptoServiceProvider(cp);  

			// Display the key information to the console.  
			//Debug.Log("Key added to container: : " +RemoveChars(rsa.ToXmlString(true)));  
		}

		public void GetKeyContainer(string ContainerName)  
		{  
			// Create the CspParameters object and set the key container   
			// name used to store the RSA key pair.  
			CspParameters cp = new CspParameters();  
			cp.KeyContainerName = ContainerName;  

			// Create a new instance of RSACryptoServiceProvider that accesses  
			// the key container MyKeyContainerName.  
			rsa = new RSACryptoServiceProvider(cp);  

			// Display the key information to the console.  
			// Debug.Log("Key retrieved from container : " + RemoveString(RemoveString(RemoveChars(rsa.ToXmlString(true)),"RSAKeyValueModulus"),"RSAKeyValue"));  
		} 

		public void DeleteKeyFromContainer(string ContainerName)  
		{  
			// Create the CspParameters object and set the key container   
			// name used to store the RSA key pair.  
			CspParameters cp = new CspParameters();  
			cp.KeyContainerName = ContainerName;  

			// Create a new instance of RSACryptoServiceProvider that accesses  
			// the key container.  
			rsa = new RSACryptoServiceProvider(cp);  

			// Delete the key entry in the container.  
			rsa.PersistKeyInCsp = false;  

			// Call Clear to release resources and delete the key from the container.  
			rsa.Clear();  

			//Debug.Log("Key deleted.");  
		}  

		public void CreateFolder(string folderHeader){
			SaveFolder newfolder = new SaveFolder();
			newfolder.header = folderHeader;

			saveFolderLib.Add(folderHeader,newfolder);
		}

		public SaveDoc CreateDoc(string folderh, string docheader){
			if(saveFolderLib.ContainsKey(folderh)==false){
				CreateFolder(folderh);
			}
			return saveFolderLib[folderh].CreateDoc(docheader);
		}

		public SaveDoc GetDoc(string folderh, string docheader){
			if(saveFolderLib.ContainsKey(folderh)){
				return saveFolderLib[folderh].GetDoc(docheader);
			}
			return null;
		}

		public string SerializeSave(){

			StreamEncapsulator encapsulator = new StreamEncapsulator();

			Dictionary<string,string> rawData = new Dictionary<string,string>();

			foreach(KeyValuePair<string,SaveFolder> kvp in saveFolderLib){
				rawData.Add(kvp.Key,kvp.Value.SerializeFolder());
			}

			return encapsulator.LoadData(rawData,"/%%/");
		}

		public void DeSerializeSave(string filedata){
			StreamEncapsulator encapsulator = new StreamEncapsulator();
			Dictionary<string,string> rawfData = new Dictionary<string,string>();

			rawfData = encapsulator.UnloadData(filedata,"/%%/");
			foreach(KeyValuePair<string,string> kvp in rawfData){
				SaveFolder newF = new SaveFolder();
				newF.DeSerializeSave(kvp.Value);
				saveFolderLib.Add(newF.header,newF);
			}
		}

		public void Save(){

			//write to a text file
			System.IO.StreamWriter file = new System.IO.StreamWriter(datapath+"/"+filepath);
			string data = SerializeSave();
			//Debug.Log("data saved: "+data);
			StreamEncapsulator encapsulator = new StreamEncapsulator();
			file.WriteLine(encapsulator.CompressString(Encrypt(encapsulator.CompressString(data))));
			file.Close();
		}

		public void Load(){

			string data = File.ReadAllText(datapath+"/"+filepath);
			StreamEncapsulator encapsulator = new StreamEncapsulator();
			data = encapsulator.DecompressString(Decrypt(encapsulator.DecompressString(data)));
			//Debug.Log("data: "+data);
			DeSerializeSave(data);
		}

		public void SaveTo(string fpath, string data){
			//write to a text file
			System.IO.StreamWriter file = new System.IO.StreamWriter(fpath);
			StreamEncapsulator encapsulator = new StreamEncapsulator();
			file.WriteLine(data);
			file.Close();
		}

		public string LoadFrom(string fpath){
			string data = File.ReadAllText(fpath);
			return data;
		}

		public string Encrypt (string toEncrypt)
		{
			//you want to change this
			string Inputkey = "12345999992234567890123456789012";
			if(rsa!=null){
				Inputkey = RemoveString(RemoveString(RemoveChars(rsa.ToXmlString(true)),"RSAKeyValueModulus"),"RSAKeyValue");
			}
			if(password!="")Inputkey = password; //password overrides everything
			var saltArray = Encoding.ASCII.GetBytes("saltystuff");
			//V2
			if (Inputkey.Length < 130) {
				for (int i = 0; i < 3; i++) {
					Inputkey += Inputkey;
				}
			} //V2 end

			var keyArray = new Rfc2898DeriveBytes(Inputkey, saltArray);

			// 256-AES key
			byte[] toEncryptArray = UTF8Encoding.UTF8.GetBytes (toEncrypt);
			RijndaelManaged rDel = new RijndaelManaged ();
			rDel.Key = keyArray.GetBytes(rDel.KeySize / 8);
			rDel.Mode = CipherMode.ECB;
			rDel.Padding = PaddingMode.PKCS7;
			// better lang support
			ICryptoTransform cTransform = rDel.CreateEncryptor ();
			byte[] resultArray = cTransform.TransformFinalBlock (toEncryptArray, 0, toEncryptArray.Length);
			return Convert.ToBase64String (resultArray, 0, resultArray.Length);
		}

		private byte[] CreateKey(string password, int keyBytes = 32)
		{
			const int Iterations = 300;
			var saltArray = Encoding.ASCII.GetBytes("saltystuff");
			var keyGenerator = new Rfc2898DeriveBytes(password, saltArray, Iterations);
			return keyGenerator.GetBytes(keyBytes);
		}

		public string EncryptCBC(string message, string IVString)
		{

			string Inputkey = password; //password overrides everything if filled
			var saltArray = Encoding.ASCII.GetBytes("saltystuff");
			byte[] Key = CreateKey (Inputkey);
			byte[] IV = ASCIIEncoding.UTF8.GetBytes(IVString);

			string encrypted = null;
			RijndaelManaged rj = new RijndaelManaged();
			rj.Key = Key;
			rj.IV = IV;
			rj.Mode = CipherMode.CBC;

			try
			{
				MemoryStream ms = new MemoryStream();

				using (CryptoStream cs = new CryptoStream(ms, rj.CreateEncryptor(Key, IV), CryptoStreamMode.Write))
				{
					using (StreamWriter sw = new StreamWriter(cs))
					{
						sw.Write(message);
						sw.Close();
					}
					cs.Close();
				}
				byte[] encoded = ms.ToArray();
				encrypted = Convert.ToBase64String(encoded);

				ms.Close();
			}
			catch (CryptographicException e)
			{
				Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
				return null;
			}
			catch (UnauthorizedAccessException e)
			{
				Console.WriteLine("A file error occurred: {0}", e.Message);
				return null;
			}
			catch (Exception e)
			{
				Console.WriteLine("An error occurred: {0}", e.Message);
			}
			finally
			{
				rj.Clear();
			}
			return encrypted;
		}

		// Decrypt a string into a string using a key and an IV 
		public string DecryptCBC(string cipherData, string ivString)
		{
			string Inputkey = password; //password overrides everything
			var saltArray = Encoding.ASCII.GetBytes("saltystuff");
			byte[] key = CreateKey (Inputkey);
			byte[] iv  = Encoding.UTF8.GetBytes(ivString);

			try
			{
				using (var rijndaelManaged =
					new RijndaelManaged {Key = key, IV = iv, Mode = CipherMode.CBC})
				using (var memoryStream = 
					new MemoryStream(Convert.FromBase64String(cipherData)))
				using (var cryptoStream =
					new CryptoStream(memoryStream,
						rijndaelManaged.CreateDecryptor(key, iv),
						CryptoStreamMode.Read))
				{
					return new StreamReader(cryptoStream).ReadToEnd();
				}
			}
			catch (CryptographicException e)
			{
				Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
				return null;
			}
			// You may want to catch more exceptions here...
		}

		public string Decrypt (string toDecrypt)
		{
			// byte[] keyArray = UTF8Encoding.UTF8.GetBytes ("12345678992234567890123456789012");
			string Inputkey = "12345999992234567890123456789012";
			if(rsa!=null){
				Inputkey = RemoveString(RemoveString(RemoveChars(rsa.ToXmlString(true)),"RSAKeyValueModulus"),"RSAKeyValue");
			}
			if(password!="")Inputkey = password; //password overrides everything

			var saltArray = Encoding.ASCII.GetBytes("saltystuff");
			//V2
			if (Inputkey.Length < 130) {
				for (int i = 0; i < 3; i++) {
					Inputkey += Inputkey;
				}
			} //V2 end

			var keyArray = new Rfc2898DeriveBytes(Inputkey, saltArray);

			// AES-256 key
			byte[] toEncryptArray = Convert.FromBase64String (toDecrypt);
			RijndaelManaged rDel = new RijndaelManaged ();
			rDel.Key = keyArray.GetBytes(rDel.KeySize / 8);
			rDel.Mode = CipherMode.ECB;
			// http://msdn.microsoft.com/en-us/library/system.security.cryptography.ciphermode.aspx
			rDel.Padding = PaddingMode.PKCS7;
			// better lang support
			ICryptoTransform cTransform = rDel.CreateDecryptor ();
			byte[] resultArray = cTransform.TransformFinalBlock (toEncryptArray, 0, toEncryptArray.Length);
			return UTF8Encoding.UTF8.GetString (resultArray);
		}

		string RemoveChars(string string_input) {
			if(string_input == null) return null;
            string_input = string_input.Replace("\n", string.Empty);
            string_input = string_input.Replace("\r", string.Empty);
            string_input = string_input.Replace("\t", string.Empty);
            string_input = string_input.Replace("<", string.Empty);
            string_input = string_input.Replace(">", string.Empty);
            string_input = string_input.Replace("/", string.Empty);
            string_input = string_input.Replace("=", string.Empty);
            string_input = string_input.Replace("+", string.Empty);
        return string_input;
		}

		string RemoveString(string orig, string removetext){
			return orig.Replace(removetext, string.Empty);
		}

		public string MD5Hash(string input)
		{

			// step 1, calculate MD5 hash from input
			MD5 md5 = System.Security.Cryptography.MD5.Create();
			byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
			byte[] hash = md5.ComputeHash(inputBytes);

			// step 2, convert byte array to hex string
			string sb = "";
			for (int i = 0; i < hash.Length; i++)
			{
				sb += hash[i].ToString();
			}
			return sb;

		}

	}

	public class StreamEncapsulator{

		public Dictionary<string,string> UnloadData(string data, string seperator){
			Dictionary<string,string> libdata = new Dictionary<string,string>();
			string[] endCapped = Regex.Split(data, seperator+":_e:");
			string[] vdata = Regex.Split(endCapped[0], seperator+"::");
			foreach(string vp in vdata){
				string[] entry = Regex.Split(vp, seperator+":,:"); // this is reserved
				if(entry.Length==2 && libdata.ContainsKey(entry[0])==false){
					libdata.Add(entry[0],entry[1]);
				}else{
					//if(libdata.ContainsKey(entry[0])) Debug.Log(entry[0]+ " exists...");
					//if (entry.Length != 2)
					//Debug.Log ("entry length is " + entry.Length);
					//Debug.Log("error sep: " + seperator + " || entry: "+ vp); //seems to be redundancy from thread split and encode
				}
			}
			return libdata;
		}

		public string LoadData(Dictionary<string,string> data, string seperator){
			string vdata = "";
			bool isFirst = true;
			foreach(KeyValuePair<string,string> kvp in data){
				if(isFirst==false){
					vdata += seperator+"::"; //data seperator
				}else{
					isFirst=false;
				}
				vdata += kvp.Key + seperator+":,:" + kvp.Value;
			}

			vdata += seperator+":_e:"+new Random().Next(1, 999);//end cap

			return vdata;
		}

		//require both origstr and newstr to be packed with the same seperator
		public string Concat(string origstr, string newstr, string seperator){
			string vdata = origstr;
			vdata += seperator+"::" + newstr;
			return vdata;
		}

		public string CompressString(string text)
		{
			byte[] buffer = Encoding.UTF8.GetBytes(text);
			var memoryStream = new MemoryStream();
			using (var gZipStream = new GZipStream(memoryStream, CompressionMode.Compress, true))
			{
				gZipStream.Write(buffer, 0, buffer.Length);
			}

			memoryStream.Position = 0;

			var compressedData = new byte[memoryStream.Length];
			memoryStream.Read(compressedData, 0, compressedData.Length);

			var gZipBuffer = new byte[compressedData.Length + 4];
			Buffer.BlockCopy(compressedData, 0, gZipBuffer, 4, compressedData.Length);
			Buffer.BlockCopy(BitConverter.GetBytes(buffer.Length), 0, gZipBuffer, 0, 4);
			return Convert.ToBase64String(gZipBuffer);
		}

		public string DecompressString(string compressedText)
		{
			byte[] gZipBuffer = Convert.FromBase64String(compressedText);
			using (var memoryStream = new MemoryStream())
			{
				int dataLength = BitConverter.ToInt32(gZipBuffer, 0);
				memoryStream.Write(gZipBuffer, 4, gZipBuffer.Length - 4);

				var buffer = new byte[dataLength];

				memoryStream.Position = 0;
				using (var gZipStream = new GZipStream(memoryStream, CompressionMode.Decompress))
				{
					gZipStream.Read(buffer, 0, buffer.Length);
				}

				return Encoding.UTF8.GetString(buffer);
			}
		}
	}
