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
using System;

namespace SecureAuthCert
{
	public class KeyValidator
	{
		public KeyValidator ()
		{
		}

		string keyIV = "akabar1820acmedo"; //change this in RegKeyGen as well

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

		public bool CheckValidationNotExpired(string prodkey, string validationKey){
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

			//store expirey date
			string FMT = "O";
			DateTime currDate = DateTime.Now;

			//store expiry date
			string privdsExp = privds.DecryptCBC (GetX(dat,"xxp",prodkey),keyIV); 
			DateTime xPrivdsDate = DateTime.ParseExact(privdsExp, FMT, CultureInfo.InvariantCulture);

			int result = DateTime.Compare(currDate, xPrivdsDate);  
			if (result <= 0) {
				return true; //val key not expired, cur date is before or equal xdate
			}
			return false;
		}
			
		//Only save this
		//final check to make sure validation key and access key matches
		public bool ValidateKeys(string prodkey, string validationKey, string accesskey, bool isInit=false){
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

			// use true key to decrypt
			DataProcessor trueKeyDS = new DataProcessor();
			trueKeyDS.password = trueKey;

			//unpack validation key
			StreamEncapsulator ixfactory = new StreamEncapsulator();
			string dataOut = trueKeyDS.DecryptCBC(encapsulator.DecompressString(accesskey),keyIV);
			Dictionary<string,string> datx = ixfactory.UnloadData (ixfactory.DecompressString (dataOut), "/%d_");
			string accessKey = trueKeyDS.DecryptCBC(GetX(datx,"xtk",prodkey),keyIV);

			//store ecrypted date hash using access key
			//note: this is used to check if the access key is valid
			DataProcessor accessKeyDS = new DataProcessor();
			accessKeyDS.password = accessKey;
			string srKey = accessKeyDS.DecryptCBC(GetX(datx,"xdk",prodkey),keyIV);

			//store expirey date
			string FMT = "O";
			DateTime currDate = DateTime.Now; 

			//store expiry date
			string privdsExp = accessKeyDS.DecryptCBC(GetX(datx,"xpd",prodkey),keyIV); 
			DateTime xPrivdsDate = DateTime.ParseExact(privdsExp, FMT, CultureInfo.InvariantCulture);

            if (isInit && srKey == (dhsh + privk)) return true;
			if(srKey == (dhsh + privk) && CheckValidationNotExpired(prodkey,validationKey)){

				int result = DateTime.Compare(currDate, xPrivdsDate);  
				if (result <= 0) {
					return true; //val key not expired, cur date is before or equal xdate
				}
				return false;

			}

			return false;
		}
	}
}

