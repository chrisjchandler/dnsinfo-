DNS Query API
Because sometimes, you just need to query DNS records and you can't do it with a dig or nslookup.

What is this?
It's an API. It queries DNS records. You send it a domain and a record type, it gives you an answer. It's not rocket science.

How to Use
Start the Server: Run go run . or go build followed by ./your-binary-name If you can't figure this out, maybe reconsider your career choices.

Make Requests: Use curl, Postman, or whatever floats your boat. 


Example:

bash
Copy code
curl "http://localhost:8080/dns-query?domain=msitproject.site&nameserver=1.1.1.1"
Replace msitproject.site with your desired domain, and 1.1.1.1 with your preferred nameserver, if you have a preference.

This is sample output from that curl

{"a":["129.146.40.194"],"mx":["eforward5.registrar-servers.com.","eforward4.registrar-servers.com.","eforward1.registrar-servers.com.","eforward2.registrar-servers.com.","eforward3.registrar-servers.com."],"ns":["dns1.registrar-servers.com.","dns2.registrar-servers.com."],"txt":["v=spf1 include:spf.efwd.registrar-servers.com ~all"]}


Get Results: The API spits back JSON with DNS record info. If there's nothing, it means there's nothing. 

Features
Queries A, AAAA, CNAME, MX, NS, TXT records – the whole gang.
Uses github.com/miekg/dns too cool for the standard net package.
Lets you specify a nameserver


Limitations
Doesn't make coffee.
Won't do your laundry.
Might be overkill if you just want an IP address.
Why Use This?
Maybe you're a sysadmin, or maybe you're just nosy. Whatever your reasons, I don't judge. you crave DNS info, this gets it for you. End of story.

Contributing
Found a bug? Open an issue. 

License
Do what you want with it I don't care
