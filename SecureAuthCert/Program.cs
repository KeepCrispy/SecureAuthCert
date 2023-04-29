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

using System;
using System.Globalization;

namespace SecureAuthCert
{
	class MainClass
	{
		public static void Main (string[] args)
		{
			ScreenWindowManager swm = new ScreenWindowManager ();
			KeyUI ku = new KeyUI (); 
			ku.InitUI (swm);

			if (args.Length <= 0) {
				while (swm.isActive) {
					swm.DisplayCurrentScreen ();
				}
			}
		}

		public static void GenRandomKey(){
			string prodkey = "demoproductkey2050";//master serial key
			string secretkey = "magicalSecret2050";//no one knows
			string serverkey = "superserverKey2050";//only server knows

			const string FMT = "O";
			DateTime now1 = DateTime.Now;
			string strDate = now1.ToString(FMT);
			DateTime now2 = DateTime.ParseExact(strDate, FMT, CultureInfo.InvariantCulture);
			Console.WriteLine(now1.ToBinary());
			Console.WriteLine(now2.ToBinary());

			Console.WriteLine ("Starting....");
			//init
			KeyManager kmg = new KeyManager ();

			string valCert = kmg.GenerateValidationKey (prodkey, secretkey, "mint2018", new DateTime(2050,12,25));
			Console.WriteLine ("key generated:");
			Console.WriteLine (valCert);
			Console.WriteLine ("-------------------------------");
			Console.WriteLine ("checking validation key:");
			if (kmg.ValidateValKey (valCert, prodkey, secretkey)) {
				Console.WriteLine ("Validation key check passed");
			} else {
				Console.WriteLine ("Validation key check failed");
			}
			Console.WriteLine ("-------------------------------");
			Console.WriteLine ("generating access key:");
			string accessCert = kmg.GenerateAccessKey (prodkey, secretkey, valCert, "access2018", new DateTime(2050,12,25));
			Console.WriteLine (accessCert);
			Console.WriteLine ("-------------------------------");
			Console.WriteLine ("checking key origins:");
			if (kmg.ValidateKeyOrigin (prodkey, valCert, accessCert,secretkey)) {
				Console.WriteLine ("key origin validation passed");
			} else {
				Console.WriteLine ("key origin  validation failed");
			}
			Console.WriteLine ("-------------------------------");
			Console.WriteLine ("checking serial key (using validation manager):");
			if (new ValidationManager().ValidateKeys (prodkey, valCert, accessCert, true)) {
				Console.WriteLine ("serial key validation passed");
			} else {
				Console.WriteLine ("serial key validation failed");
			}
			Console.WriteLine ("-------------------------------");
			Console.WriteLine ("generating service key:");
			string serviceKey = kmg.GenServiceKey (prodkey, valCert, accessCert);
			Console.WriteLine (serviceKey);
			Console.WriteLine ("-------------------------------");
			Console.WriteLine ("check service key pass:");
			string keypass = kmg.GetServiceKey (prodkey, valCert, accessCert, serviceKey, true);
			Console.WriteLine (keypass);
			Console.WriteLine ("-------------------------------");
			Console.WriteLine ("generating server key:");
			string serverCert = kmg.GenServerValidationKeys (prodkey, valCert, serverkey, "server2018");
			Console.WriteLine (serverCert);
			Console.WriteLine ("-------------------------------");
			Console.WriteLine ("checking server key:");
			if (kmg.ValidateServerKey (prodkey, valCert, serverkey, serverCert)) {
				Console.WriteLine ("server key validation passed");
			} else {
				Console.WriteLine ("server key validation failed");
			}
		}
	}
}
