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
using System.Linq;
using System;
using System.IO;

namespace SecureAuthCert
{
	public class KeyUI
	{
		public KeyUI ()
		{
		}

		public void InitUI(ScreenWindowManager swm){
			ScreenWindow title = new ScreenWindow ();
			title.textDisplay = "\n" +
            "Welcome to SecureAuthCert Service\n" +
            "Copyright(c) 2023 RYW\n" +
            "--------------------------------------------\n" +
			"what would you like to do today?\n" +
			"1 - Generate random key\n" +
			"2 - Generate new cert\n" +
			"3 - Generate from cert\n" +
			"--------------------------------------------";
			title.onHandleInputEvent += (i, mn) => {
				if (i == "1") {
					MainClass.GenRandomKey ();
					mn.isActive = false;//exit prog
				}
				if(i == "2"){
					mn.currentScreen = "gencert1";
				}
				if(i == "3"){
					mn.currentScreen = "cert1";
				}
			};
			swm.AddWindow ("title", title);
			swm.currentScreen = "title";

			InitGenCert (swm);
			InitaccessKeyGen (swm);

			
		}

		public void InitGenCert(ScreenWindowManager swm){
			
			ScreenWindow gencertGen1 = new ScreenWindow ();
			gencertGen1.textDisplay = "\n" +
				"Generate new cert\n" +
				"--------------------------------------------\n" +
				"please enter file name: \n" +
				"--------------------------------------------";
			gencertGen1.onHandleInputEvent += (i, mn) => {
				//go to access key gen
				gencertGen1.memoryData["filename"] = i;
				mn.currentScreen = "gencert2";
			};
			swm.AddWindow ("gencert1", gencertGen1);


			ScreenWindow gencertGen2 = new ScreenWindow ();
			gencertGen2.textDisplay = "\n" +
				"Generate new cert -> Settings 1/3\n" +
				"--------------------------------------------\n" +
				"please enter product key\n" +
				"--------------------------------------------";
			gencertGen2.onHandleInputEvent += (i, mn) => {
				//go to access key gen
				gencertGen1.memoryData["productkey"] = i;
				mn.currentScreen = "gencert3";
			};
			swm.AddWindow ("gencert2", gencertGen2);

			ScreenWindow gencertGen3 = new ScreenWindow ();
			gencertGen3.textDisplay = "\n" +
				"Generate new cert -> Settings 2/3\n" +
				"--------------------------------------------\n" +
				"please enter secret key\n" +
				"--------------------------------------------";
			gencertGen3.onHandleInputEvent += (i, mn) => {
				//go to access key gen
				gencertGen1.memoryData["secretkey"] = i;
				mn.currentScreen = "gencert4";
			};
			swm.AddWindow ("gencert3", gencertGen3);

			ScreenWindow gencertGen4 = new ScreenWindow ();
			gencertGen4.textDisplay = "\n" +
				"Generate new cert -> Settings 3/3\n" +
				"--------------------------------------------\n" +
				"please enter expiry time (months)\n" +
				"--------------------------------------------";
			gencertGen4.onHandleInputEvent += (i, mn) => {
				//go to access key gen
				gencertGen1.memoryData["month"] = i;
				mn.currentScreen = "gencert5";
			};
			swm.AddWindow ("gencert4", gencertGen4);

			ScreenWindow gencertGen5 = new ScreenWindow ();
			gencertGen5.textDisplay = "\n" +
				"Generate new cert -> Settings 3/3\n" +
				"--------------------------------------------\n" +
				"please enter expiry time (months)\n" +
				"--------------------------------------------";
			gencertGen5.hasInput = false;
			gencertGen5.onHandleActive += (mn) => {
				//run prog
				string certfile = mn.GetWindow("gencert1").memoryData["filename"];
				string prodkey = mn.GetWindow("gencert1").memoryData["productkey"];
				string secretkey = mn.GetWindow("gencert1").memoryData["secretkey"];
				string months = mn.GetWindow("gencert1").memoryData["month"];

				string dataPath = AppDomain.CurrentDomain.BaseDirectory;

				KeyManager kmg = new KeyManager ();
				DateTime expirydate = new DateTime();
				int mnths = 1;
				int.TryParse(months, out mnths);
				expirydate.AddMonths(mnths);

				string valCert = kmg.GenerateValidationKey (prodkey, secretkey, "mint2018", expirydate);
				Console.WriteLine ("keygenerated:");
				Console.WriteLine (valCert);
				Console.WriteLine ("-------------------------------");
				Console.WriteLine ("checking validation key:");
				if (kmg.ValidateValKey (valCert, prodkey, secretkey)) {
					Console.WriteLine ("Validation key check passed");
				} else {
					Console.WriteLine ("Validation key check failed");
				}
				File.WriteAllText(dataPath+"/"+certfile,valCert);
				mn.isActive = false;
			};
			swm.AddWindow ("gencert5", gencertGen5);
		}


		public void InitaccessKeyGen(ScreenWindowManager swm){

			ScreenWindow certGen1 = new ScreenWindow ();
			certGen1.textDisplay = "\n" +
				"Generate from cert\n" +
				"--------------------------------------------\n" +
				"what key do you want to generate from CERT?\n" +
				"1 - access Key\n" +
				"2 - Server Key ** not implemented yet **\n" +
				"--------------------------------------------";
			certGen1.onHandleInputEvent += (i, mn) => {
				if(i == "1"){
					//go to access key gen
					mn.currentScreen = "cert2access";
				}
				if(i == "2"){
					//go to server key gen
				}
			};
			swm.AddWindow ("cert1", certGen1);

			ScreenWindow certGen2 = new ScreenWindow ();
			certGen2.textDisplay = "\n" +
				"Generate from cert -> access Key\n" +
				"--------------------------------------------\n" +
				"please input cert file name\n" +
				"--------------------------------------------";
			certGen2.onHandleInputEvent += (i, mn) => {
				certGen2.memoryData["filename"] = i;
				mn.currentScreen = "cert3access";
			};
			swm.AddWindow ("cert2access", certGen2);

			ScreenWindow certGen3 = new ScreenWindow ();
			certGen3.textDisplay = "\n" +
				"Generate from cert -> access Key\n" +
				"--------------------------------------------\n" +
				"please output key file name\n" +
				"--------------------------------------------";
			certGen3.onHandleInputEvent += (i, mn) => {
				certGen3.memoryData["keyfilename"] = i;
				mn.currentScreen = "cert4access";
			};
			swm.AddWindow ("cert3access", certGen3);

			ScreenWindow certGen4 = new ScreenWindow ();
			certGen4.textDisplay = "\n" +
				"Generating from cert -> access Key -> Settings 1/3\n" +
				"------------------------------------------------------------\n" +
				"please input product key\n" +
				"------------------------------------------------------------";
			certGen4.onHandleInputEvent += (i, mn) => {
				certGen4.memoryData["productkey"] = i;
				mn.currentScreen = "cert5access";
			};
			swm.AddWindow ("cert4access", certGen4);

			ScreenWindow certGen5 = new ScreenWindow ();
			certGen5.textDisplay = "\n" +
				"Generating from cert -> access Key -> Settings 2/3\n" +
				"------------------------------------------------------------\n" +
				"please input secret key\n" +
				"------------------------------------------------------------";
			certGen5.onHandleInputEvent += (i, mn) => {
				certGen5.memoryData["secretkey"] = i;
				mn.currentScreen = "cert6access";
			};
			swm.AddWindow ("cert5access", certGen5);

			ScreenWindow certGen6 = new ScreenWindow ();
			certGen6.textDisplay = "\n" +
				"Generating from cert -> access Key -> Settings 3/3\n" +
				"------------------------------------------------------------\n" +
				"please input life of access Key (months)\n" +
				"------------------------------------------------------------";
			certGen6.onHandleInputEvent += (i, mn) => {
				certGen6.memoryData["months"] = i;
				mn.currentScreen = "cert7access";
			};
			swm.AddWindow ("cert6access", certGen6);

			ScreenWindow certGen7 = new ScreenWindow ();
			certGen7.textDisplay = "\n" +
				"Generating from cert -> access Key\n" +
				"------------------------------------------------------------\n";
			certGen7.hasInput = false;
			certGen7.onHandleActive += (mn) => {
				//run prog
				string certfile = mn.GetWindow("cert2access").memoryData["filename"];
				string keyfile = mn.GetWindow("cert3access").memoryData["keyfilename"];
				string prodkey = mn.GetWindow("cert4access").memoryData["productkey"];
				string secretkey = mn.GetWindow("cert5access").memoryData["secretkey"];
				string months = mn.GetWindow("cert6access").memoryData["months"];

				string dataPath = AppDomain.CurrentDomain.BaseDirectory;

				string certData = File.ReadAllText(dataPath +"/"+ certfile);

				//init
				KeyManager kmg = new KeyManager ();
				DateTime expirydate = new DateTime();
				int mnths = 1;
				int.TryParse(months, out mnths);
				expirydate.AddMonths(mnths);
				Console.WriteLine ("generating access key:");
				string accessCert = kmg.GenerateAccessKey (prodkey, secretkey, certData, "access2018", expirydate);
				Console.WriteLine (accessCert);
				Console.WriteLine ("-------------------------------");
				Console.WriteLine ("checking key origins:");
				if (kmg.ValidateKeyOrigin (prodkey, certData, accessCert,secretkey)) {
					Console.WriteLine ("key origin validation passed");
				} else {
					Console.WriteLine ("key origin  validation failed");
				}

				File.WriteAllText(dataPath+"/"+keyfile, accessCert);
				//end window
				mn.isActive = false;
				//exit
			};
			swm.AddWindow ("cert7access", certGen7);
		}
	}
}

