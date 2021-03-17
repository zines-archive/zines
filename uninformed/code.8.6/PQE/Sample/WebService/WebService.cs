//
// Cthulhu: binary analysis framework
//
// Overview
//
//    Implements a fake web service that contains potential vulnerabilities.
//
// Author
//
//    7/2007   Matt Miller [mmiller@hick.org] 
//
using System;
using System.Collections.Generic;
using System.Text;

using System.Web.Services;

namespace WebService
{
	/// <summary>
	/// A typical web service class definition
	/// </summary>
	[WebService]
	public class WebService
	{
		/// <summary>
		/// Simulates a web service command that executes a program
		/// </summary>
		/// <param name="command">The command string to execute</param>
		[WebMethod]
		public void ExecuteCommand(string command)
		{
			// Launches the command without any validation...
			System.Diagnostics.Process.Start(command);
		}
	}
}
