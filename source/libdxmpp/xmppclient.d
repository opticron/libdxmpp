// Project Name: libxmpd
/* Project Description: 
 *	A class based on phobos that connects to a XMPP server.  This includes jabber, jingle, and any other xmpp-based protocol.
 *	Until I get this working properly, everything will be hardcoded to jabber.
*/
module libdxmpp.xmppclient;
import libdsha.sha1;
import std.thread : Thread;
debug(libxmpd)import std.stdio : writefln;
import std.string;
import std.socket;
import object;
// these two dependencies need to be grabbed by whatever is using this module
import futures.future;
import kxml.xml;

// we need this for buddy list support
struct rosterItem {
	// the fully qualified jabber name
	string userid;
	// this is the alias you've set for this user
	string name;
	// i'm not sure if you can be in multiple groups or not, so you only get the first one for now
	string group;
	// this is going to be either none, to, from, or both
	string subscription;
}

class XMPPClient {
	private {
		string server,username,password,domain,resource;
		ushort port;
		string sessionid,digest;
		// our locks
		Object resplist;
		Object cbsetlock;

		// callbacks for errors, incoming messages, and presence info
		// param is the connection error message
		void function(XMPPClient,string) connerrcb;
		// params are user and message
		void function(XMPPClient,string,string)msgcb;
		// params are user, type, and status
		void function(XMPPClient,string,string,string) prescb;
		// associative part is the username
		// first string is the type ("away"/"available"/etc)
		// second string is the actual message (e.g."I'm at the store")
		string[2][string]presinfo;

		// variables to manage the connection
		Thread runthread;
		string buffer;
		Socket connection;
		bool isStreaming;
		bool running;
		bool authenticated;
		XmlNode[string]responseList;
	}
	public void setAddress(string address,ushort connectport = 5222,string serverdomain = "") {
		port = connectport;
		server = address;
		domain = serverdomain;
	}
	public void setCreds(string user,string pass,string res = "libxmpd") {
		username = user;
		password = pass;
		resource = res;
	}
	this () {
		isStreaming = false;
		running = false;
		authenticated = false;
		resplist = new Object();
		cbsetlock = new Object();
	}
	// this is going to be based on function pointers and will spawn a thread internally
	void setConnErrCB(void function(XMPPClient,string)errcb) {
		synchronized (cbsetlock) {
			connerrcb = errcb;
		}
	}
	void setMessageCB(void function(XMPPClient,string,string)inmsgcb) {
		synchronized (cbsetlock) {
			msgcb = inmsgcb;
		}
	}
	void setPresCB(void function(XMPPClient,string,string,string)inprescb) {
		synchronized (cbsetlock) {
			prescb = inprescb;
		}
	}
	bool sendMessage (string userid,string message) {
		// make sure that we've authenticated with the server before attempting to send messages


		XmlNode xml = new XmlNode("message");
		xml.setAttribute("type","chat").setAttribute("id",getNewID).setAttribute("to",userid);
		xml.addChild((new XmlNode("body")).addCData(message));
		// this is trippy
		xml.addChild(
			(new XmlNode("html")).setAttribute("xmlns","http://jabber.org/protocol/xhtml-im").addChild(
				(new XmlNode("body")).addCData(message).setAttribute("xmlns","http://www.w3.org/1999/xhtml")
			)
		);
		if (isStreaming && authenticated) {
			// do stuff here to send a message
			sendRaw(xml.toString());
			return true;
		} else {
			return false;
		}
	}
	void setPresence(string type,string message) {
		if (isStreaming && authenticated) {
			// build presence structure
			XmlNode xml = new XmlNode("presence");
			xml.addChild((new XmlNode("priority")).addCData("1"));
			xml.addChild((new XmlNode("show")).addCData(type));
			xml.addChild((new XmlNode("status")).addCData(message));
			// i'm going to reuse query
			XmlNode tmp = new XmlNode("c");
			tmp.setAttribute("xmlns","http://jabber.org/protocol/caps").setAttribute("node","http://pidgin.im/caps");
			tmp.setAttribute("ver","2.4.1").setAttribute("ext","moodn nickn tunen avatar");
			xml.addChild(tmp);
			sendRaw(xml.toString());
		}
	}

	// this returns the raw data inside the response IQ element
	XmlNode sendIQ(string responseid,string type,XmlNode IQ) {
		XmlNode xml = new XmlNode("iq");
		xml.setAttribute("id",responseid);
		xml.setAttribute("type",type);
		xml.setAttribute("to",domain);
		xml.addChild(IQ);
		// set ourselves to wait for the response
		responseList[responseid] = null;
		if (isStreaming) sendRaw(xml.toString());
		else return null;
		bool waiting = true;
		while (waiting) {
			// sleep a millisecond between checks
			Socket.select(null,null,null,1000);
			synchronized (resplist) waiting = (responseList[responseid] is null);
		}
		synchronized (resplist) return responseList[responseid];
	}

	void sendRaw (string data) {
		debug(libxmpd)writefln("Sending: "~data);
		synchronized (connection) connection.send(data);
	}

	// throws an exception on failure
	void Connect() {
		if (runthread is null) {
			runthread = new Thread(&runProtocol);
			runthread.start();
			// wait for the thread to kick off before going anywhere
			// this needs to be fail-safed somehow, the thread could fail before reaching the "running" stage
			// and this would sit here forever
			while (!running){Socket.select(null,null,null,1000);}
			// since the thread is kicked off, let's do auth
			doAuth();
		}
	}

	// let the user close the connection
	void Disconnect() {
		if (runthread !is null) {
			// barf some raw junk at the server
			sendRaw("</stream:stream>");
			synchronized (connection) connection.close();
			// i really hope this is enough to kill the thread, but somehow i know it won't be
			// so i'm hoping the connection loss will take care of that for me
			runthread = null;
		}
	}

	// generate all IDs here
	string getNewID() {
		// make sure we start with 0....
		static packetcount = -1;
		packetcount++;
		return "libxmpd"~std.string.toString(packetcount);
	}

	// allow the user to sit and wait on this
	void wait() {
		if (runthread !is null) {
			runthread.wait();
		}
	}

	// the digest is a sha1 hex hash of the stream ID and the pass concatenated 
	// the stream ID comes from the id attribute of the opening stream:stream element from the server
	private void doAuth() {
		XmlNode xml,tmp;
		// build the opening stream tag and xml header, the root node is blank
		xml = new XmlNode();
		xml.addChild((new XmlPI("xml")).setAttribute("version","1.0"));
		tmp = new XmlNode("stream:stream");
		tmp.setAttribute("to",domain).setAttribute("xmlns","jabber:client");
		tmp.setAttribute("xmlns:stream","http://etherx.jabber.org/streams").setAttribute("version","1.0");
		xml.addChild(tmp);

		// we have to do this to make the stream tag non self-closing as the protocol requires
		// cuts off the /> and adds >
		sendRaw(xml.toString()[0..$-2]~">");
		// now we need to wait until the remote end opens it's stream
		while (!isStreaming){Socket.select(null,null,null,1000);}
		// respid, type, data
		xml = new XmlNode("query");
		xml.setAttribute("xmlns","jabber:iq:auth");
		xml.addChild( (new XmlNode("username")).addCData(username) );
		xml = sendIQ(getNewID,"get",xml);
		// check for error or lack of response within timeout
		if (xml is null || xml.getAttribute("type").icmp("error") == 0) {
			debug(libxmpd) writefln("BARF: Got an error from the server");
			if (connerrcb !is null) connerrcb(this,xml.toString());
			Disconnect();
			runthread = null;
			// something broke....
			return;
		}
		// since we have the return structure and it isn't junk, we want to tweak it and lob it back
		auto digest = sha1HexString(sessionid~password);
		// tweak query node
		if (xml.getChildren().length && (tmp = xml.getChildren()[0]).getName().icmp("query") == 0) {
			foreach (child;tmp.getChildren()) {
				// cdata for the resource and digest should be blank, so no need for removal
				auto name = child.getName();
				if (name.icmp("resource") == 0) {
					child.addCData(resource);
				} else if (name.icmp("digest") == 0) {
					child.addCData(digest);
				} else if (name.icmp("username") == 0 && child.getCData() == "") {
					child.addCData(username);
				} else if (name.icmp("password") == 0) {
					child.addCData(password);
				}
			}
		} else {
			debug(libxmpd) writefln("BARF: Got an error from the server");
			if (connerrcb !is null) connerrcb(this,xml.toString());
			Disconnect();
			runthread = null;
			// something broke and we need to do something better to handle the situation
			return;
		}
		// send the modified xml packet
		xml = sendIQ(getNewID,"set",tmp);
		digest = xml.getAttribute("type");
		if (digest !is null && digest.icmp("error") == 0) {
			debug(libxmpd) writefln("BARF: Got an error from the server");
			if (connerrcb !is null) connerrcb(this,xml.toString());
			Disconnect();
			runthread = null;
			// more broken shit
			return;
		}
		authenticated = true;

		// we probably shouldn't do this here, but enable presence messages by setting presence
		setPresence("available","");
	}

	// i don't THINK this needs any arguments....
	rosterItem[] getBuddyList() {
		// build the xml packet
		XmlNode packet = new XmlNode("query");
		packet.setAttribute("xmlns","jabber:iq:roster");
		packet = sendIQ(getNewID,"",packet);
		// iterate through children which should be item nodes
		rosterItem[] blist;
		foreach(child;packet.getChildren) if (child.getName().icmp("item") == 0) {
			rosterItem item;
			// grab the necessary data
			item.userid = child.getAttribute("jid");
			item.name = child.getAttribute("name");
			item.subscription = child.getAttribute("subscription");
			// make sure we clear this in case there is no group
			item.group = "";
			foreach(group;child.getChildren) if (group.getName().icmp("group") == 0) {
				// this may need to be modified if we have to keep track of multiple groups per user
				// would also have to modify the structure
				item.group = group.getCData;
			}
			blist ~= item;
		}
		return blist;
	}

	// libxmpp ALWAYS runs in a thread
	// otherwise, we can't do auth properly
	private int runProtocol() {
		connection = new TcpSocket(new InternetAddress(server,port));
		assert(connection.isAlive);
		connection.blocking = false;
		debug(libxmpd)writefln("Connected to %s on port %d.",server, cast(int)port);
		running = true;
		SocketSet sset = new SocketSet(1);
	
		while(true) {
			sset.add(connection);
			Socket.select(sset, null, null);
			debug(libxmpd)writefln("Processing event...");
			if (sset.isSet(connection)) {
				char[2048] buf;
				int read;
				synchronized (connection) read = connection.receive(buf);
				if (read != Socket.ERROR && read > 0) {
					buffer ~= buf[0 .. read];
					// make sure we get ALL the data before attempting a parse
					if (read == 1024) {
						SocketSet single = new SocketSet(1);
						single.add(connection);
						// using socket.select to figure out whether there is data available is really annoying
						while (Socket.select(single,null,null,0) > 0) {
							synchronized (connection) read = connection.receive(buf);
							buffer ~= buf[0 .. read];
							single.add(connection);
							debug(libxmpd)writefln("Reading more parts of the packet!");
						}
					}
					if (!handleXML()) return 0;
				} else if (read == Socket.ERROR || read == 0) {
					debug(libxmpd)writefln("LibXMPD Connection error!");
					// release socket resources
					synchronized (connection) connection.close();
					// remove buffer
					buffer = "";
					// call connection error delegate
					connerrcb(this,"Connection error!");
					return 1;
				}
			} else {
				// if we hit this, we have issues
				connerrcb(this,"Connection error!");
				return 1;
			}
		}
		return 0;
	}
	
	private int handleXML() {
		// this function has direct access to both the connection and the buffer if needed
		XmlNode xml;
		string tmp = null;
		try {
			// check for the opening stream
			debug(libxmpd)writefln("parsing: "~buffer);
			if (!isStreaming && buffer.find("<stream:stream") != -1) {
				debug(libxmpd)writefln("Found an opening stream tag!");
				// tack on a closing tag so this crap parses right
				// yeah, i know it's a hack...fuck xml streams
				buffer ~= "</stream:stream>";
				xml = readDocument(buffer);
				XmlNode tmpnode;
				foreach (child;xml.getChildren()) {
					if (child.getName().icmp("stream:stream") == 0) {
						if ((sessionid = child.getAttribute("id")) is null) {
							// we have a protocol error here.....
							return 1;
						}
						// the sessionid has already been captured
						tmpnode = child;
						break;
					}
				}
				// get ready to process any subnodes
				xml = tmpnode;
				isStreaming = true;
			} else if (isStreaming && buffer.find("</stream:stream>") != -1) {
				debug(libxmpd)writefln("Found a closing stream tag!");
				// our session is closed, so we need to exit
				isStreaming = false;
				// close the socket
				if (connection !is null) synchronized (connection) connection.close();
				return 0;
			} else {
				xml = readDocument(buffer);
			}
			// since it always comes back with a blank root node, we need to get the first child that's packet
			foreach (XmlNode child;xml.getChildren()) if (!child.isCData()) {
				// this is where we spawn threads
				if (child.getName().icmp("iq") == 0){
					debug(libxmpd)writefln("Got an IQ tag!");
					future(&handleIQ,child);
				} else if (child.getName().icmp("message") == 0){
					debug(libxmpd)writefln("Got a message!");
					future(&handleMessage,child);
				} else if (child.getName().icmp("presence") == 0){
					debug(libxmpd)writefln("Got presence!");
					future(&handlePresence,child);
				} else {
					debug(libxmpd)writefln("Unknown tag: "~child.toString());
					tmp ~= child.toString();
				}
			} else {
				debug(libxmpd)writefln("Junk CData: "~child.toString());
				tmp ~= child.toString();
			}
			buffer = tmp;
		} catch (Exception e) {
			debug(libxmpd)writefln(e.toString());
			// return code for failure
			return 0;
		}

		return 1;
	}

	// always look for type="error" as a failure case
	/* Breakdown of the xml structures in the jabber protocol
	// Note: closing tags seem to be non-requisite if there are no more tags in the packet
	//	<iq><query>... is valid, but <iq><query><query> is not, it would have to be <iq><query></query><query>
	<iq id="" type="">
	* Possible subtags
		<query>this can have various tags in it such as username, resource, item, digest, depends on the xmlns attribute</query> 
	</iq>
	*/
	private void handleIQ(XmlNode IQ) {
		debug(libxmpd)writefln("Parsing IQ tag from server");
		// here, we're going to assume that the IQ tags are all properly formed xml, cause my brain lives in candy land
		// when i find out otherwise (which i will), i'll build lazy parsing into kxml, but we need the basic code structure first
		// first, see if the id on this thing matches something we're waiting for
		auto id = IQ.getAttribute("id");
		bool isWaiting;
		synchronized (resplist) isWaiting = ((id in responseList) !is null);
		if (id !is null && isWaiting) {
			// we're waiting for this response somewhere
			// make this better, doesn't need the iq itself, just all the data inside
			synchronized (resplist) responseList[id] = IQ;
			return;
		}
		// since it wasn't handled already, we have something new
		auto type = IQ.getAttribute("type");
		// barf on no id
		if (id is null) {
			debug(libxmpd)writefln("Got a iq tag with no packet, how fun...dropping it");
			return;
		}
		// barf on no type
		if (type is null) {
			debug(libxmpd)writefln("Barf on packet with id=%s since there is no type attribute",id);
			return;
		}
		// that should catch most of the errors, now for some down and dirty parsing
		// as far as i can tell, all of them contain a query subnode
	}

	// yank the vital data out of the message and lob it toward the callback (which we hope was set by the user)
	private void handleMessage(XmlNode message) {
		// i hope we can assume this message was meant for us since it made it here....
		auto from = message.getAttribute("from");
		if (from is null) {
			// we need to barf here or something
			return;
		}
		string msg = null;
		// we may have to look in the html tag if we can't find it here....
		foreach(child;message.getChildren()) {
			if (!child.isCData() && child.getName().icmp("body") == 0) {
				msg = child.getCData();
			}
		}
		// the message was blank or didn't have a body element, it was probably some sort of update from the remote end
		// with either an active or composing tag
		if (msg == "") {
			return;
		}
		if (msgcb !is null) {
			msgcb(this,from,msg);
		}
	}

	private void handlePresence(XmlNode presence) {
		// i hope we can assume this message was meant for us since it made it here....
		auto from = presence.getAttribute("from");
		if (from is null) {
			// we need to barf here or something
			return;
		}
		string type = null;
		string status = null;
		// we may have to look in the html tag if we can't find it here....
		foreach(child;presence.getChildren()) if (!child.isCData()) {
			// we're looking for show and status tags, we don't currently care about the rest
			if (child.getName().icmp("show") == 0) {
				type = child.getCData();
			} else if (child.getName().icmp("status") == 0) {
				status = child.getCData();
			}
		}
		if (prescb !is null && type != "") {
			// save this data for future reference
			presinfo[from][0] = type;
			presinfo[from][1] = status;
			prescb(this,from,type,status);
		}
	}

	public bool getPresData(string user,ref string type,ref string status) {
		if ((user in presinfo) !is null) {
			type = presinfo[user][0];
			status = presinfo[user][1];
			return true;
		}
		return false;
	}
}

