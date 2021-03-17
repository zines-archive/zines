//
// Cthulhu: binary analysis framework
//
// Overview
//
//    Implements a fake web client that invokes commands on a web service.
//
// Author
//
//    7/2007   Matt Miller [mmiller@hick.org] 
//
using System;
using System.Collections.Generic;
using System.Text;

using System.Web.Services;
using System.Web.Services.Protocols;
using System.Web;
using System.Web.UI.WebControls;

namespace WebClient
{
	class Program
	{
		static void Main(string[] args)
		{
			HttpRequest request = new HttpRequest("a", "b", "c");
			WebClient client = new WebClient();

			client.ExecuteCommand(request.QueryString["abc"]);
		}
	}

	/// <summary>
	/// Encapsulates communication with the web service
	/// </summary>
	[WebServiceBinding]
	public class WebClient : SoapHttpClientProtocol
	{
		/// <summary>
		/// Executes a command on the web service
		/// </summary>
		/// <param name="command">The command to execute</param>
		[SoapDocumentMethod]
		public void ExecuteCommand(string command)
		{
			Invoke("ExecuteCommand", new object[] { command });
		}
	}
}
