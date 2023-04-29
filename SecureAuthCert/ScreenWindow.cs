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
	public class ScreenWindow
	{
		public string textDisplay = "";
		public string screenName = "";

		public System.Action<string,ScreenWindowManager> onHandleInputEvent = (s,m) => {};
		public System.Action<ScreenWindowManager> onHandleActive = (m) => {};

		public Dictionary<string,string> memoryData = new Dictionary<string, string>();

		public bool hasInput = true;

		public ScreenWindow ()
		{
		}

		public void DisplayText(){
			Console.Write (textDisplay);
			Console.Out.Flush();
			Console.WriteLine ("");
		}

		public void HandleInput(string data, ScreenWindowManager swm){
			onHandleInputEvent (data,swm);
		}

		public void HandleOnActivate(ScreenWindowManager swm){
			onHandleActive (swm);
		}
	}
}

