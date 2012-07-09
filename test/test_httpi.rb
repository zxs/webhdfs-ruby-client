require 'httpi'
require 'krb5_auth'

krb5 = Krb5Auth::Krb5.new
#krb5.get_init_creds_password('zen', 'abc123')
krb5.get_init_creds_keytab("hdfs/api.0.efoxconn.com", "/etc/hadoop/conf/hdfs.keytab")
krb5.cache


HTTPI.adapter = :curb #  one of [:httpclient, :curb, :net_http]

request = HTTPI::Request.new
request.url = "http://api.0.efoxconn.com:14000/webhdfs/v1?op=gethomedirectory"
request.auth.gssnegotiate 
response = HTTPI.request :get,request
puts response.code
puts response.headers
puts response.body


krb5.destroy
