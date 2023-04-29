using System.Collections;
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
	public class ScreenWindowManager
	{
		public ScreenWindowManager ()
		{
		}

		public bool isActive = true;

		public Dictionary<string,ScreenWindow> _windowMap = new Dictionary<string,ScreenWindow>();

		public string currentScreen = "";

		public void DisplayCurrentScreen(){
			Console.Clear ();
			ScreenWindow sw = _windowMap [currentScreen];
			sw.DisplayText ();
			sw.HandleOnActivate (this);
			if (sw.hasInput) {
				Console.Write ("input> ");
				string input = Console.ReadLine ();
				sw.HandleInput (input, this);
			}
		}

		public void ExitWindow(){
			isActive = false;
		}

		public void SetCurrentWindow(string windowName){
			currentScreen = windowName;
		}

		public ScreenWindow GetWindow(string windowName){
			return _windowMap [windowName];
		}

		public void AddWindow(string windowName, ScreenWindow swin){
			_windowMap [windowName] = swin;
		}

	}
}

