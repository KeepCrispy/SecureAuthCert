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
using System.Globalization;
using System.Linq;
using System;

namespace SecureAuthCert
{
	public class RegKeyGen
	{
		public RegKeyGen ()
		{
		}
		   
		/*
		 * Note for use:
		 * prodkey is stored and set in key validation program
		 * 
		 * secret key is only used for creating validation keys and serial keys
		 * secret key is not stored anywhere
		 * 
		 * validation key can match multi server keys
		 * validation key can match multi serial keys
		 * 
		 * TODO - convert all dictionary hashes to encrypted strings
		 */

		string keyIV = "akabar1820acmedo";

		//generates a validation key
		public string GenerateValidationKey(string prodkey, string secretkey, string mintData, DateTime expiryDate){
			/* dictionary draft
			 * 
			 * pub prodkey
			 * note: product key is stored in program and changes
			 * 
			 * compress -> pack (prodkey{
				 *  hash checksum
				 * 	string hsh1 = ds.MD5Hash (pwd + "hashkeyx");
					dat ["hx"] = ds.Encrypt (ds.MD5Hash(hsh1 + "passwordmx")); //double hash
				 * hashed datestamp = (double hash + prodkey + double hash) -> (hash time stamp)
				 * privkey = (prodkey + datestamp)->(secretkey)
				 * true key = secretkey ->("##_" datestamp + random_password + hsh1)
				 * note: true key unlocks serial key
				 * })
			 */
			//init
			DataProcessor ds = new DataProcessor();
			Dictionary<string,string> dat = new Dictionary<string, string> ();
			ds.password = prodkey;

			//double hash check sum
			string hsh = ds.MD5Hash (prodkey + "hashkeyxxvvyy");
			string hsh2 = ds.MD5Hash (hsh + "passwordmx");
			dat [EncX("xh",prodkey)] = ds.EncryptCBC (hsh2 + "xvxvhash808",keyIV); //double hash

			//date and date hash

			DateTime dt = DateTime.Today;
			string st = dt.ToString("MM.dd.yyyy") + DateTime.Now.ToString("HH:mm:ss tt");
			int dHashSerial = new Random().Next(1, 10000000);
			string dhsh = ds.MD5Hash (st + "datehashyxxvvyy"+dHashSerial);
			dat [EncX("xdh",prodkey)] = ds.EncryptCBC (dhsh,keyIV);

			//create private key
			DataProcessor privds = new DataProcessor();  
			privds.password = prodkey + dhsh;
			string privatekey = ds.MD5Hash(secretkey) + dhsh + "p1807880mx";
			string privk = privds.EncryptCBC (privatekey,keyIV);
			dat [EncX("xpk",prodkey)] = privk;

			//private key date
			const string FMT = "O";
			DateTime now1 = DateTime.Now;
			string strDate = now1.ToString(FMT);
			dat [EncX("xbh",prodkey)] = privds.EncryptCBC (strDate,keyIV);

			//secret key and dhsh - encrypted serial
			DataProcessor ssk = new DataProcessor();
			ssk.password = privatekey;
			string randomSalt = new Random().Next(1, 1000)+RandomString(12);
			dat [EncX("xbk",prodkey)] = ssk.EncryptCBC (strDate+randomSalt,keyIV); 

			//store expirey date
			string expDateData = expiryDate.ToString(FMT);
			dat [EncX("xpd",prodkey)] = ssk.EncryptCBC (expDateData,keyIV); 

			//store expirey date hash
			string expDateHash = expiryDate.ToString(FMT);
			dat [EncX("xhs",prodkey)] = ssk.EncryptCBC (ds.MD5Hash(expDateHash),keyIV); 

			//store expiry date
			string expTmDateData = expiryDate.ToString(FMT);
			dat [EncX("xxp",prodkey)] = privds.EncryptCBC (expTmDateData,keyIV); 

			//create true key
			DataProcessor tkds = new DataProcessor();
			tkds.password = privatekey;
			string randomkey = new Random().Next(1, 1000)+RandomString(12);
			string trueKey = tkds.EncryptCBC ("#_" + dhsh + randomkey + hsh,keyIV);
			dat [EncX("xtk",prodkey)] = trueKey;

			//store mint data
			string minD = tkds.Encrypt (mintData);
			dat [EncX("xmt",prodkey)] = minD;

			//add salt
			string tsalt = "" + DateTime.Now.ToString("ss") + hsh + DateTime.Now.ToString("ss") + hsh2 + DateTime.Now.ToString("ss");
			dat [EncX("xst",prodkey)] = tkds.EncryptCBC (tsalt,keyIV);

			//pack validation key
			StreamEncapsulator encapsulator = new StreamEncapsulator();
			string validKey = ds.EncryptCBC(encapsulator.CompressString(encapsulator.LoadData (dat, "/%d_")),keyIV);
			return validKey;
		}

		private string EncX(string tgt, string pwd){
			DataProcessor ds = new DataProcessor();
			ds.password = pwd + "xyz" + pwd;
			return ds.EncryptCBC (tgt,keyIV);
		}

		private string GetX(Dictionary<string,string> dat, string tgt, string pwd){
			//init
			DataProcessor ds = new DataProcessor();
			ds.password = pwd + "xyz" + pwd;
			string etgt = ds.EncryptCBC (tgt,keyIV);
			foreach (KeyValuePair<string,string> kvp in dat) {
				if (kvp.Key == etgt) {
					return kvp.Value;
				}
			}
			return "";
		}

		public bool ValidateValKey(string valkey, string prodkey, string secretkey){
			//init
			DataProcessor ds = new DataProcessor();
			ds.password = prodkey;

			//double hash check sum
			string hsh = ds.MD5Hash (prodkey + "hashkeyxxvvyy");
			string hsh2 = ds.MD5Hash (hsh + "passwordmx");

			//unpack validation key
			StreamEncapsulator encapsulator = new StreamEncapsulator();
			string data = ds.DecryptCBC (valkey,keyIV);
			Dictionary<string,string> dat = encapsulator.UnloadData (encapsulator.DecompressString (data), "/%d_");

			//get datehash
			string dhsh = ds.DecryptCBC (GetX(dat,"xdh",prodkey),keyIV);

			//get private key
			DataProcessor privds = new DataProcessor();
			privds.password = prodkey + dhsh;
			string privk = privds.DecryptCBC (GetX(dat,"xpk",prodkey),keyIV);

			//get birthdaykey
			//secret key and dhsh - encrypt birthday
			DataProcessor ssk = new DataProcessor();
			ssk.password = ds.MD5Hash(secretkey) + dhsh + "p1807880mx";
			string certSerial = ssk.DecryptCBC (GetX(dat,"xbk",prodkey),keyIV); 

			//get expiry dates
			//store expirey date
			string FMT = "O";
			string sskExp= ssk.DecryptCBC (GetX(dat,"xpd",prodkey),keyIV); 
			DateTime xSskDate = DateTime.ParseExact(sskExp, FMT, CultureInfo.InvariantCulture);

			//store expiry date
			string privdsExp = privds.DecryptCBC (GetX(dat,"xxp",prodkey),keyIV); 
			DateTime xPrivdsDate = DateTime.ParseExact(privdsExp, FMT, CultureInfo.InvariantCulture);

			if (privk == (ds.MD5Hash(secretkey)+dhsh+ "p1807880mx")) {
				int result = DateTime.Compare(xPrivdsDate, xSskDate);  
				if (result == 0) {
					return true; //val key not expired, cur date is before or equal xdate
				}
			}
			return false;

		}

		public bool CheckValidationNotExpired(string prodkey, string validationKey){
			//init
			DataProcessor ds = new DataProcessor();
			ds.password = prodkey;

			//unpack validation key
			StreamEncapsulator encapsulator = new StreamEncapsulator();
			string data = ds.DecryptCBC(validationKey,keyIV);
			Dictionary<string,string> dat = encapsulator.UnloadData (encapsulator.DecompressString (data), "/%d_");

			//get datehash
			string dhsh = ds.DecryptCBC(GetX(dat,"xdh",prodkey),keyIV);

			//get private key
			DataProcessor privds = new DataProcessor();
			privds.password = prodkey + dhsh;
			string privk = privds.DecryptCBC(GetX(dat,"xpk",prodkey),keyIV);

			//store expirey date
			string FMT = "O";
			DateTime currDate = DateTime.Now;

			//store expiry date
			string privdsExp = privds.DecryptCBC(GetX(dat,"xxp",prodkey),keyIV); 
			DateTime xPrivdsDate = DateTime.ParseExact(privdsExp, FMT, CultureInfo.InvariantCulture);

			int result = DateTime.Compare(currDate, xPrivdsDate);  
			if (result <= 0) {
				return true; //val key not expired, cur date is before or equal xdate
			}
			return false;
		}

		//generate serial key
		//note: need keyData["vk"] = "validation key" from above
		public string GenerateAccessKey(string prodkey, string secretkey, string validationKey, string mintData, DateTime expiryDate){

			//init
			DataProcessor ds = new DataProcessor();
			ds.password = prodkey;

			//unpack validation key
			StreamEncapsulator encapsulator = new StreamEncapsulator();
			string data = ds.DecryptCBC(validationKey,keyIV);
			Dictionary<string,string> dat = encapsulator.UnloadData (encapsulator.DecompressString (data), "/%d_");

			//get datehash
			string dhsh = ds.DecryptCBC(GetX(dat,"xdh",prodkey),keyIV);

			//get private key
			DataProcessor privds = new DataProcessor();
			privds.password = prodkey + dhsh;
			string privk = privds.DecryptCBC(GetX(dat,"xpk",prodkey),keyIV);

			//get true key
			DataProcessor tkds = new DataProcessor();
			tkds.password = privk;
			string trueKey = tkds.DecryptCBC(GetX(dat,"xtk",prodkey),keyIV);

			//get birthdaykey
			//secret key and dhsh - encrypt birthday
			DataProcessor ssk = new DataProcessor();
			ssk.password = ds.MD5Hash(secretkey) + dhsh + "p1807880mx";
			string certSerial = ssk.DecryptCBC(GetX(dat,"xbk",prodkey),keyIV); 

			//---------------------------------generating serial key-----------------------------------
			// note: prod key and secret key is never used from here out

			// use true key to encrypt
			DataProcessor trueKeyDS = new DataProcessor();
			trueKeyDS.password = trueKey;

			//new serial key dictionary
			Dictionary<string,string> xdat = new Dictionary<string, string>();

			//double hash
			string hsh = ds.MD5Hash (trueKey + "hashkeyxxvvyy");
			string hsh2 = ds.MD5Hash (hsh + "pmxxxjj");
			xdat [EncX("xh",prodkey)] = ds.EncryptCBC(hsh2 + "xvxuuhshhsh",keyIV); //double hash

			//create serial key
			//note: true key unlocks serial key
			string randomkey = new Random().Next(1, 1000)+RandomString(12);
			string serialKey = "#_" + dhsh + randomkey + hsh;
			xdat [EncX("xtk",prodkey)] = trueKeyDS.EncryptCBC(serialKey,keyIV);

			//store ecrypted date hash using serial key
			//note: this is used to check if the serial key is valid
			DataProcessor serialKeyDS = new DataProcessor();
			serialKeyDS.password = serialKey;
			xdat [EncX("xdk",prodkey)] = serialKeyDS.EncryptCBC(dhsh+privk,keyIV);

			//store date created
			string FMT = "O";
			DateTime now1 = DateTime.Now;
			string strDate = now1.ToString(FMT);
			xdat [EncX("xbh",prodkey)] = serialKeyDS.EncryptCBC(strDate,keyIV);

			//store expiry date
			string expDateData = expiryDate.ToString(FMT);
			xdat [EncX("xpd",prodkey)] = serialKeyDS.EncryptCBC(expDateData,keyIV); 

			//store birthdaykey
			xdat[EncX("xbk",prodkey)] = serialKeyDS.EncryptCBC(certSerial,keyIV);

			//store mint data
			string minD = serialKeyDS.EncryptCBC(mintData,keyIV);
			xdat [EncX("xmt",prodkey)] = minD;

			//add salt
			string tsalt = "" + DateTime.Now.ToString("ss") + hsh + DateTime.Now.ToString("ss") + hsh2 + DateTime.Now.ToString("ss");
			xdat [EncX("xst",prodkey)] = tkds.EncryptCBC(tsalt,keyIV);

			//pack serial key
			StreamEncapsulator ixfactory = new StreamEncapsulator();
			string validKey = ixfactory.CompressString(trueKeyDS.EncryptCBC(ixfactory.CompressString(ixfactory.LoadData (xdat, "/%d_")),keyIV));
			return validKey;
		}

		public bool CheckValKeyAlive(string prodkey, string validationKey){
			//init
			DataProcessor ds = new DataProcessor();
			ds.password = prodkey;

			//unpack validation key
			StreamEncapsulator encapsulator = new StreamEncapsulator();
			string data = ds.DecryptCBC(validationKey,keyIV);
			Dictionary<string,string> dat = encapsulator.UnloadData (encapsulator.DecompressString (data), "/%d_");

			//get datehash
			string dhsh = ds.DecryptCBC(GetX(dat,"xdh",prodkey),keyIV);

			//get private key
			DataProcessor privds = new DataProcessor();
			privds.password = prodkey + dhsh;
			string privk = privds.DecryptCBC(GetX(dat,"xpk",prodkey),keyIV);

			//store expiry date
			string FMT = "O";
			string expDate = privds.DecryptCBC(GetX(dat,"xxp",prodkey),keyIV); 
			DateTime xDate = DateTime.ParseExact(expDate, FMT, CultureInfo.InvariantCulture);
			DateTime curDate = DateTime.Now;
			int result = DateTime.Compare(curDate, xDate);  
			if (result <= 0) {
				return true; //val key not expired, cur date is before or equal xdate
			}
			return false; // val key has expired, result >= 1, cur date passed xdate
		}

		public bool ValidateKeyOrigin(string prodkey, string validationKey, string serialkey, string secretkey){
			//init
			DataProcessor ds = new DataProcessor();
			ds.password = prodkey;

			//unpack validation key
			StreamEncapsulator encapsulator = new StreamEncapsulator();
			string data = ds.DecryptCBC(validationKey,keyIV);
			Dictionary<string,string> dat = encapsulator.UnloadData (encapsulator.DecompressString (data), "/%d_");

			//get datehash
			string dhsh = ds.DecryptCBC(GetX(dat,"xdh",prodkey),keyIV);

			//get private key
			DataProcessor privds = new DataProcessor();
			privds.password = prodkey + dhsh;
			string privk = privds.DecryptCBC(GetX(dat,"xpk",prodkey),keyIV);

			//get true key
			DataProcessor tkds = new DataProcessor();
			tkds.password = privk;
			string trueKey = tkds.DecryptCBC(GetX(dat,"xtk",prodkey),keyIV);

			//secret key and dhsh - encrypt birthday
			DataProcessor ssk = new DataProcessor();
			ssk.password = ds.MD5Hash(secretkey) + dhsh + "p1807880mx";
			string certSerial = ssk.DecryptCBC(GetX(dat,"xbk",prodkey),keyIV); 

			//-----------------------------------------------------------------------------

			// use true key to decrypt
			DataProcessor trueKeyDS = new DataProcessor();
			trueKeyDS.password = trueKey;

			//unpack validation key
			StreamEncapsulator ixfactory = new StreamEncapsulator();
			string dataOut = trueKeyDS.DecryptCBC(encapsulator.DecompressString(serialkey),keyIV);
			Dictionary<string,string> datx = ixfactory.UnloadData (ixfactory.DecompressString (dataOut), "/%d_");
			string serialKey = trueKeyDS.DecryptCBC(GetX(datx,"xtk",prodkey),keyIV);

			//store ecrypted date hash using serial key
			//note: this is used to check if the serial key is valid
			DataProcessor serialKeyDS = new DataProcessor();
			serialKeyDS.password = serialKey;

			//store birthdaykey
			string serialCert = serialKeyDS.DecryptCBC(GetX(datx,"xbk",prodkey),keyIV);

			if (serialCert == certSerial) {
				return true;
			}
			return false;
		}

		//final check to make sure validation key and serial key matches
		public bool ValidateKeys(string prodkey, string validationKey, string serialkey, bool isInit)
        {
			//init
			DataProcessor ds = new DataProcessor();
			ds.password = prodkey;

			//unpack validation key
			StreamEncapsulator encapsulator = new StreamEncapsulator();
			string data = ds.DecryptCBC(validationKey,keyIV);
			Dictionary<string,string> dat = encapsulator.UnloadData (encapsulator.DecompressString (data), "/%d_");

			//get datehash
			string dhsh = ds.DecryptCBC(GetX(dat,"xdh",prodkey),keyIV);

			//get private key
			DataProcessor privds = new DataProcessor();
			privds.password = prodkey + dhsh;
			string privk = privds.DecryptCBC(GetX(dat,"xpk",prodkey),keyIV);

			//get true key
			DataProcessor tkds = new DataProcessor();
			tkds.password = privk;
			string trueKey = tkds.DecryptCBC(GetX(dat,"xtk",prodkey),keyIV);

			//-----------------------------------------------------------------------------

			// use true key to decrypt
			DataProcessor trueKeyDS = new DataProcessor();
			trueKeyDS.password = trueKey;

			//unpack validation key
			StreamEncapsulator ixfactory = new StreamEncapsulator();
			string dataOut = trueKeyDS.DecryptCBC(encapsulator.DecompressString(serialkey),keyIV);
			Dictionary<string,string> datx = ixfactory.UnloadData (ixfactory.DecompressString (dataOut), "/%d_");
			string serialKey = trueKeyDS.DecryptCBC(GetX(datx,"xtk",prodkey),keyIV);

			//store ecrypted date hash using serial key
			//note: this is used to check if the serial key is valid
			DataProcessor serialKeyDS = new DataProcessor();
			serialKeyDS.password = serialKey;
			string srKey = serialKeyDS.DecryptCBC(GetX(datx,"xdk",prodkey),keyIV);

			//store expirey date
			string FMT = "O";
			DateTime currDate = DateTime.Now; 

			//store expiry date
			string privdsExp = serialKeyDS.DecryptCBC(GetX(datx,"xpd",prodkey),keyIV); 
			DateTime xPrivdsDate = DateTime.ParseExact(privdsExp, FMT, CultureInfo.InvariantCulture);

            if (isInit && srKey == (dhsh + privk)) return true;

            if (srKey == (dhsh + privk) && CheckValidationNotExpired(prodkey,validationKey)){
				
					int result = DateTime.Compare(currDate, xPrivdsDate);  
					if (result <= 0) {
						return true; //val key not expired, cur date is before or equal xdate
					}
					return false;

				}

			return false;
		}

		//generates a service only random key, using validation key to unlock serialkey file -> serial key (used to encrypt random encryption key)
		public string GenServiceKeys(string prodkey, string validationKey, string serialkey, bool isInit){
			if (ValidateKeys (prodkey, validationKey, serialkey, isInit)) {
				
				//init
				DataProcessor ds = new DataProcessor();
				ds.password = prodkey;

				//unpack validation key
				StreamEncapsulator encapsulator = new StreamEncapsulator();
				string data = ds.DecryptCBC(validationKey,keyIV);
				Dictionary<string,string> dat = encapsulator.UnloadData (encapsulator.DecompressString (data), "/%d_");

				//get datehash
				string dhsh = ds.DecryptCBC(GetX(dat,"xdh",prodkey),keyIV);

				//get private key
				DataProcessor privds = new DataProcessor();
				privds.password = prodkey + dhsh;
				string privk = privds.DecryptCBC(GetX(dat,"xpk",prodkey),keyIV);

				//get true key
				DataProcessor tkds = new DataProcessor();
				tkds.password = privk;
				string trueKey = tkds.DecryptCBC(GetX(dat,"xtk",prodkey),keyIV);

				//-----------------------------------------------------------------------------

				// use true key to decrypt serial key
				DataProcessor trueKeyDS = new DataProcessor();
				trueKeyDS.password = trueKey;

				//unpack validation key
				StreamEncapsulator ixfactory = new StreamEncapsulator();
				string dataOut = trueKeyDS.DecryptCBC(encapsulator.DecompressString(serialkey),keyIV);
				Dictionary<string,string> datx = ixfactory.UnloadData (ixfactory.DecompressString (dataOut), "/%d_");
				string serialKeyPass = trueKeyDS.DecryptCBC(GetX(datx,"xtk",prodkey),keyIV);

				//-----------------------------------------------------------------------------
				//start creating service key

				DataProcessor serialKeyDS = new DataProcessor();
				serialKeyDS.password = serialKeyPass;

				//new serial key dictionary
				Dictionary<string,string> xdat = new Dictionary<string, string>();

				//store date created
				string FMT = "O";
				DateTime now1 = DateTime.Now;
				string strDate = serialKeyDS.MD5Hash(now1.ToString(FMT)) + RandomString(32);
				xdat[EncX("xscx",prodkey)] = serialKeyDS.EncryptCBC(strDate,keyIV);

				//add salt
				string tsalt = "" + DateTime.Now.ToString("ss") + dhsh + DateTime.Now.ToString("ss") + new Random().Next(1, 10000000) + DateTime.Now.ToString("ss");
				xdat [EncX("xst",prodkey)] = tkds.EncryptCBC (tsalt,keyIV);

				//pack key
				StreamEncapsulator ixxfactory = new StreamEncapsulator();
				string validKey = ixxfactory.CompressString(serialKeyDS.EncryptCBC(ixxfactory.CompressString(ixxfactory.LoadData (xdat, "/%d_")),keyIV));
				return validKey;
			}
			return "";
		}

		public string GetServiceKey(string prodkey, string validationKey, string serialkey, string serviceKey, bool isInit){
			if (ValidateKeys (prodkey, validationKey, serialkey, isInit)) {

				//init
				DataProcessor ds = new DataProcessor();
				ds.password = prodkey;

				//unpack validation key
				StreamEncapsulator encapsulator = new StreamEncapsulator();
				string data = ds.DecryptCBC (validationKey,keyIV);
				Dictionary<string,string> dat = encapsulator.UnloadData (encapsulator.DecompressString (data), "/%d_");

				//get datehash
				string dhsh = ds.DecryptCBC (GetX(dat,"xdh",prodkey),keyIV);

				//get private key
				DataProcessor privds = new DataProcessor();
				privds.password = prodkey + dhsh;
				string privk = privds.DecryptCBC (GetX(dat,"xpk",prodkey),keyIV);

				//get true key
				DataProcessor tkds = new DataProcessor();
				tkds.password = privk;
				string trueKey = tkds.DecryptCBC (GetX(dat,"xtk",prodkey),keyIV);

				//-----------------------------------------------------------------------------

				// use true key to decrypt serial key
				DataProcessor trueKeyDS = new DataProcessor();
				trueKeyDS.password = trueKey;

				//unpack validation key
				StreamEncapsulator ixfactory = new StreamEncapsulator();
				string dataOut = trueKeyDS.DecryptCBC(encapsulator.DecompressString(serialkey),keyIV);
				Dictionary<string,string> datx = ixfactory.UnloadData (ixfactory.DecompressString (dataOut), "/%d_");
				string serialKeyPass = trueKeyDS.DecryptCBC(GetX(datx,"xtk",prodkey),keyIV);

				//-----------------------------------------------------------------------------
				//start unpacking service key
				try{
					DataProcessor serialKeyDS = new DataProcessor();
					serialKeyDS.password = serialKeyPass;

					//unpack service key
					StreamEncapsulator isxfactory = new StreamEncapsulator();
					string dataXOut = serialKeyDS.DecryptCBC(isxfactory.DecompressString(serviceKey),keyIV);
					Dictionary<string,string> datxo = isxfactory.UnloadData (isxfactory.DecompressString (dataXOut), "/%d_");
					string servicesKey = serialKeyDS.DecryptCBC(GetX(datxo,"xscx",prodkey),keyIV);

					return servicesKey;

				}catch(Exception e){
					Console.WriteLine ("service key, 10");
					return "";
				}
			}
			return "";
		}

		private static Random random = new Random();
		public string RandomString(int length)
		{
			const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
			return new string(Enumerable.Repeat(chars, length)
				.Select(s => s[random.Next(s.Length)]).ToArray());
		}

		//generate server validation keys
		public string GenServerValidationKeys(string prodKey, string validationKey, string serverKey, string mintData){
			//init
			DataProcessor ds = new DataProcessor();
			ds.password = prodKey;

			//unpack validation key
			StreamEncapsulator encapsulator = new StreamEncapsulator();
			string data = ds.DecryptCBC (validationKey,keyIV);
			Dictionary<string,string> dat = encapsulator.UnloadData (encapsulator.DecompressString (data), "/%d_");

			//get datehash
			string dhsh = ds.DecryptCBC (GetX(dat,"xdh",prodKey),keyIV);

			//get private key
			DataProcessor privds = new DataProcessor();
			privds.password = prodKey + dhsh;
			string privk = privds.DecryptCBC (GetX(dat,"xpk",prodKey),keyIV);

			//get true key
			DataProcessor tkds = new DataProcessor();
			tkds.password = privk;
			string trueKey = tkds.DecryptCBC (GetX(dat,"xtk",prodKey),keyIV);

			//-----------------------------------------------------------------------------
			//init
			DataProcessor crossEncDS = new DataProcessor();
			crossEncDS.password = dhsh;
			DataProcessor Serverds = new DataProcessor();
			Serverds.password = crossEncDS.EncryptCBC(serverKey+trueKey,keyIV);

			Dictionary<string,string> sdat = new Dictionary<string,string> ();
			sdat [EncX("xdh",prodKey)] = Serverds.EncryptCBC (dhsh,keyIV);
			string shsh = Serverds.MD5Hash (serverKey + privk + dhsh);
			sdat [EncX("xpkh",prodKey)] = Serverds.EncryptCBC (shsh,keyIV);
			string tkhsh = Serverds.MD5Hash (trueKey + serverKey);
			sdat [EncX("xtk",prodKey)] = Serverds.EncryptCBC (tkhsh,keyIV);

			//store date created
			const string FMT = "O";
			DateTime now1 = DateTime.Now;
			string strDate = now1.ToString(FMT);
			sdat [EncX("xbh",prodKey)] = Serverds.EncryptCBC (strDate,keyIV);

			//store mint data
			string minD = Serverds.EncryptCBC (mintData,keyIV);
			sdat [EncX("xmt",prodKey)] = minD;

			//add salt
			string tsalt = "" + DateTime.Now.ToString("ss") + shsh + DateTime.Now.ToString("ss") + dhsh + DateTime.Now.ToString("ss");
			sdat [EncX("xst",prodKey)] = Serverds.EncryptCBC (tsalt,keyIV);

			//server key encrypts product key and validation key hash
			//server key is only known to server

			//pack serial key
			StreamEncapsulator ixfactory = new StreamEncapsulator();
			string serverKeyFile = ixfactory.CompressString(Serverds.EncryptCBC(ixfactory.CompressString(ixfactory.LoadData (sdat, "/%d_")),keyIV));
			return serverKeyFile;
		}

		//check server key
		public bool ValidateServerKey(string prodKey, string validationKey, string serverKey, string ServerSerialKey){
			//init
			DataProcessor ds = new DataProcessor();
			ds.password = prodKey;

			//unpack validation key
			StreamEncapsulator encapsulator = new StreamEncapsulator();
			string data = ds.DecryptCBC (validationKey,keyIV);
			Dictionary<string,string> dat = encapsulator.UnloadData (encapsulator.DecompressString (data), "/%d_");

			//get datehash
			string dhsh = ds.DecryptCBC (GetX(dat,"xdh",prodKey),keyIV);

			//get private key
			DataProcessor privds = new DataProcessor();
			privds.password = prodKey + dhsh;
			string privk = privds.DecryptCBC (GetX(dat,"xpk",prodKey),keyIV);

			//get true key
			DataProcessor tkds = new DataProcessor();
			tkds.password = privk;
			string trueKey = tkds.DecryptCBC (GetX(dat,"xtk",prodKey),keyIV);

			//-----------------------------------------------------------------------------
			//init
			DataProcessor crossEncDS = new DataProcessor();
			crossEncDS.password = dhsh;
			DataProcessor Serverds = new DataProcessor();
			Serverds.password = crossEncDS.EncryptCBC(serverKey+trueKey,keyIV);

			StreamEncapsulator ixfactory = new StreamEncapsulator();
			string dataOut = Serverds.DecryptCBC(ixfactory.DecompressString(ServerSerialKey),keyIV);
			Dictionary<string,string> sdat = ixfactory.UnloadData (ixfactory.DecompressString (dataOut), "/%d_");

			string shsh = Serverds.MD5Hash (serverKey + privk + dhsh);
			string tkhsh = Serverds.MD5Hash (trueKey + serverKey);

			string dhsh_s = Serverds.DecryptCBC (GetX(sdat,"xdh",prodKey),keyIV);
			string shsh_s = Serverds.DecryptCBC (GetX(sdat,"xpkh",prodKey),keyIV);
			string tkhsh_s = Serverds.DecryptCBC (GetX(sdat,"xtk",prodKey),keyIV);
			//----------------------------------------------------------------------------

			if (dhsh == dhsh_s && shsh == shsh_s && tkhsh == tkhsh_s) {
				return true;
			}
			return false;
		}

	}
}

