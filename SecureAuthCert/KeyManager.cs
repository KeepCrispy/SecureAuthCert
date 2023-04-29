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
	//This is a Reg Key Gen Management Interface
	//Note: Master Program, do not include
	public class KeyManager
	{
		public KeyManager ()
		{
		}
		//Note: Master Program, do not include
		public string GenerateValidationKey(string prodkey, string secretkey, string mintData, DateTime expTime){
			RegKeyGen rkg = new RegKeyGen ();
			return rkg.GenerateValidationKey (prodkey, secretkey, mintData,expTime);
		}

		public bool ValidateValKey(string valkey, string prodkey, string secretkey){
			RegKeyGen rkg = new RegKeyGen ();
			return rkg.ValidateValKey (valkey, prodkey, secretkey);
		}

		//generate access key
		//note: need keyData["vk"] = "validation key" from above
		//Note: Master Program, do not include
		public string GenerateAccessKey(string prodkey, string secretkey, string validationKey, string mintData, DateTime expTime){
			RegKeyGen rkg = new RegKeyGen ();
			return rkg.GenerateAccessKey (prodkey, secretkey, validationKey, mintData, expTime);
		}

		public string GenServiceKey(string prodkey, string validationKey, string accesskey){
			RegKeyGen rkg = new RegKeyGen ();
			return rkg.GenServiceKeys(prodkey, validationKey, accesskey, true);
		}

		public string GetServiceKey(string prodkey, string validationKey, string accesskey, string serviceKey, bool isInit=false){
			RegKeyGen rkg = new RegKeyGen ();
			return rkg.GetServiceKey (prodkey, validationKey, accesskey, serviceKey, isInit);
		}

		//check if access key is from validation key
		public bool ValidateKeyOrigin(string prodkey, string validationKey, string accesskey, string secretkey){
			RegKeyGen rkg = new RegKeyGen ();
			return rkg.ValidateKeyOrigin(prodkey, validationKey, accesskey, secretkey);
		}

		//final check to make sure validation key and access key matches
		public bool ValidateKeys(string prodkey, string validationKey, string accesskey){
			RegKeyGen rkg = new RegKeyGen ();
			return rkg.ValidateKeys(prodkey, validationKey, accesskey, false);
		}

        public bool ValidateKeys(string prodkey, string validationKey, string accesskey, bool isInit)
        {
            RegKeyGen rkg = new RegKeyGen();
            return rkg.ValidateKeys(prodkey, validationKey, accesskey, isInit);
        }

        //generate server validation keys
        //Note: Master Program, do not include
        public string GenServerValidationKeys(string prodKey, string validationKey, string serverKey, string mintData){
			RegKeyGen rkg = new RegKeyGen ();
			return rkg.GenServerValidationKeys (prodKey, validationKey, serverKey, mintData);
		}

		//check server key
		public bool ValidateServerKey(string prodKey, string validationKey, string serverKey, string ServeraccessKey){
			RegKeyGen rkg = new RegKeyGen ();
			return rkg.ValidateServerKey (prodKey, validationKey, serverKey, ServeraccessKey);
		}
	}
}

