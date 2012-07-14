#require 'net/http'
require 'httpi'
require 'krb5_auth'
require 'uri'
require 'json'

require_relative 'exceptions'

module WebHDFS
  class ClientV1

    # This hash table holds command options.
    OPT_TABLE = {} # internal use only

    attr_accessor :host, :port, :username, :doas
    attr_accessor :open_timeout, :read_timeout
    attr_accessor :httpfs_mode
    attr_accessor :auth_type       # pseudo, kerberos
    attr_accessor :pass_keytab


    def initialize(host='localhost', port=14000, username=nil, doas=nil)
      @host = host
      @port = port
      @username = username
      @doas = doas

      @httpfs_mode = false
    end

    # curl -i -X PUT "http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=CREATESYMLINK&destination=<PATH>
    #                 [&createParent=<true|false>]"
    def create_symlink(path, dest, options={})
      check_options(options, OPT_TABLE['CREATESYMLINK'])
      unless dest.start_with?('/')
        dest = '/' + dest
      end
      res = operate_requests(:put, path, 'CREATESYMLINK', options.merge({'destination' => dest}))
      check_success_json(res, 'boolean')
    end
    OPT_TABLE['CREATESYMLINK'] = ['createParent']

    # curl -i -X PUT "http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=CREATE
    #                 [&overwrite=<true|false>][&blocksize=<LONG>][&replication=<SHORT>]
    #                 [&permission=<OCTAL>][&buffersize=<INT>]"
    def create(path, body, options={})
      if @httpfs_mode
        options = options.merge({'data' => 'true'})
      end
      check_options(options, OPT_TABLE['CREATE'])
      res = operate_requests(:put, path, 'CREATE', options, body)
      res.code == 201
    end
    OPT_TABLE['CREATE'] = ['overwrite', 'blocksize', 'replication', 'permission', 'buffersize', 'data']

    # curl -i -X POST "http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=APPEND[&buffersize=<INT>]"
    def append(path, body, options={})
      if @httpfs_mode
        options = options.merge({'data' => 'true'})
      end
      check_options(options, OPT_TABLE['APPEND'])
      res = operate_requests(:post, path, 'APPEND', options, body)
      res.code == 200
    end
    OPT_TABLE['APPEND'] = ['buffersize', 'data']

    # curl -i -L "http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=OPEN
    #                [&offset=<LONG>][&length=<LONG>][&buffersize=<INT>]"
    def read(path, options={})
      check_options(options, OPT_TABLE['OPEN'])
      res = operate_requests(:get, path, 'OPEN', options)
      res.body
    end
    OPT_TABLE['OPEN'] = ['offset', 'length', 'buffersize']
    alias :open :read

    # curl -i -X PUT "http://<HOST>:<PORT>/<PATH>?op=MKDIRS[&permission=<OCTAL>]"
    def mkdir(path, options={})
      check_options(options, OPT_TABLE['MKDIRS'])
      res = operate_requests(:put, path, 'MKDIRS', options)
      check_success_json(res, 'boolean')
    end
    OPT_TABLE['MKDIRS'] = ['permission']
    alias :mkdirs :mkdir

    # curl -i -X PUT "<HOST>:<PORT>/webhdfs/v1/<PATH>?op=RENAME&destination=<PATH>"
    def rename(path, dest, options={})
      check_options(options, OPT_TABLE['RENAME'])
      unless dest.start_with?('/')
        dest = '/' + dest
      end
      res = operate_requests(:put, path, 'RENAME', options.merge({'destination' => dest}))
      check_success_json(res, 'boolean')
    end

    # curl -i -X DELETE "http://<host>:<port>/webhdfs/v1/<path>?op=DELETE
    #                          [&recursive=<true|false>]"
    def delete(path, options={})
      check_options(options, OPT_TABLE['DELETE'])
      res = operate_requests(:delete, path, 'DELETE', options)
      check_success_json(res, 'boolean')
    end
    OPT_TABLE['DELETE'] = ['recursive']

    # curl -i  "http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=GETFILESTATUS"
    def stat(path, options={})
      check_options(options, OPT_TABLE['GETFILESTATUS'])
      res = operate_requests(:get, path, 'GETFILESTATUS', options)
      check_success_json(res, 'FileStatus')
    end
    alias :getfilestatus :stat

    # curl -i  "http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=LISTSTATUS"
    def list(path, options={})
      check_options(options, OPT_TABLE['LISTSTATUS'])
      res = operate_requests(:get, path, 'LISTSTATUS', options)
      check_success_json(res, 'FileStatuses')['FileStatus']
    end
    alias :liststatus :list

    # curl -i "http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=GETCONTENTSUMMARY"
    def content_summary(path, options={})
      check_options(options, OPT_TABLE['GETCONTENTSUMMARY'])
      res = operate_requests(:get, path, 'GETCONTENTSUMMARY', options)
      check_success_json(res, 'ContentSummary')
    end
    alias :getcontentsummary :content_summary

    # curl -i "http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=GETFILECHECKSUM"
    def checksum(path, options={})
      check_options(options, OPT_TABLE['GETFILECHECKSUM'])
      res = operate_requests(:get, path, 'GETFILECHECKSUM', options)
      check_success_json(res, 'FileChecksum')
    end
    alias :getfilechecksum :checksum

    # curl -i "http://<HOST>:<PORT>/webhdfs/v1/?op=GETHOMEDIRECTORY"
    def homedir(options={})
      check_options(options, OPT_TABLE['GETHOMEDIRECTORY'])
      res = operate_requests(:get, '/', 'GETHOMEDIRECTORY', options)
      check_success_json(res, 'Path')
    end
    alias :gethomedirectory :homedir

    # curl -i -X PUT "http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=SETPERMISSION
    #                 [&permission=<OCTAL>]"
    def chmod(path, mode, options={})
      check_options(options, OPT_TABLE['SETPERMISSION'])
      res = operate_requests(:put, path, 'SETPERMISSION', options.merge({'permission' => mode}))
      res.code == 200
    end
    alias :setpermission :chmod

    # curl -i -X PUT "http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=SETOWNER
    #                          [&owner=<USER>][&group=<GROUP>]"
    def chown(path, options={})
      check_options(options, OPT_TABLE['SETOWNER'])
      unless options.has_key?('owner') or options.has_key?('group') or
          options.has_key?(:owner) or options.has_key?(:group)
        raise ArgumentError, "'chown' needs at least one of owner or group"
      end
      res = operate_requests(:put, path, 'SETOWNER', options)
      res.code == 200
    end
    OPT_TABLE['SETOWNER'] = ['owner', 'group']
    alias :setowner :chown

    # curl -i -X PUT "http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=SETREPLICATION
    #                           [&replication=<SHORT>]"
    def replication(path, replnum, options={})
      check_options(options, OPT_TABLE['SETREPLICATION'])
      res = operate_requests(:put, path, 'SETREPLICATION', options.merge({'replication' => replnum.to_s}))
      check_success_json(res, 'boolean')
    end
    alias :setreplication :replication

    # curl -i -X PUT "http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=SETTIMES
    #                           [&modificationtime=<TIME>][&accesstime=<TIME>]"
    # motidicationtime: radix-10 logn integer
    # accesstime: radix-10 logn integer
    def touch(path, options={})
      check_options(options, OPT_TABLE['SETTIMES'])
      unless options.has_key?('modificationtime') or options.has_key?('accesstime') or
          options.has_key?(:modificationtime) or options.has_key?(:accesstime)
        raise ArgumentError, "'chown' needs at least one of modificationtime or accesstime"
      end
      res = operate_requests(:put, path, 'SETTIMES', options)
      res.code == 200
    end
    OPT_TABLE['SETTIMES'] = ['modificationtime', 'accesstime']
    alias :settimes :touch

    # def delegation_token(user, options={}) # GETDELEGATIONTOKEN
    #   raise NotImplementedError
    # end
    # def renew_delegation_token(token, options={}) # RENEWDELEGATIONTOKEN
    #   raise NotImplementedError
    # end
    # def cancel_delegation_token(token, options={}) # CANCELDELEGATIONTOKEN
    #   raise NotImplementedError
    # end

    def check_options(options, optdecl=[])
      ex = options.keys.map(&:to_s) - (optdecl || [])
      raise ArgumentError, "no such option: #{ex.join(' ')}" unless ex.empty?
    end

    def check_success_json(res, attr=nil)
      res.code == 200 and res.headers['Content-Type'].include?('application/json') and (attr.nil? or JSON.parse(res.body)[attr])
    end

    def api_path(path)
      if path.start_with?('/')
        '/webhdfs/v1' + path
      else
        '/webhdfs/v1/' + path
      end
    end

    def build_path(path, op, params)
      opts = if @username and @doas
               {'op' => op, 'user.name' => @username, 'doas' => @doas}
             elsif @username
               {'op' => op, 'user.name' => @username}
             elsif @doas
               {'op' => op, 'doas' => @doas}
             else
               {'op' => op}
             end
      query = URI.encode_www_form(params.merge(opts))
      api_path(path) + '?' + query
    end

    REDIRECTED_OPERATIONS = ['APPEND'] # , 'CREATE' ] , 'OPEN'], 'GETFILECHECKSUM']
    REDIRECTED_CODE = (300..399)

    def operate_requests(method, path, op, params={}, payload=nil)
      if not @httpfs_mode and REDIRECTED_OPERATIONS.include?(op)
        res = request(@host, @port, method, path, op, params, nil)
        unless REDIRECTED_CODE.include?(res.code) and res.headers['Location']
          msg = "NameNode returns non-redirection (or without location header), code:#{res.code}, body:#{res.body}."
          raise WebHDFS::RequestFailedError, msg
        end
        uri = URI.parse(res.headers['Location'])
        rpath = if uri.query
                  uri.path + '?' + uri.query
                else
                  uri.path
                end
        puts "\txxx rpath=" +rpath
        request(uri.host, uri.port, method, rpath, nil, {}, payload, {'Content-Type' => 'application/octet-stream'})
      else
        if @httpfs_mode and not payload.nil?
          request(@host, @port, method, path, op, params, payload, {'Content-Type' => 'application/octet-stream'})
        else
          request(@host, @port, method, path, op, params, payload)
        end
      end
    end

    # IllegalArgumentException      400 Bad Request
    # UnsupportedOperationException 400 Bad Request
    # SecurityException             401 Unauthorized
    # IOException                   403 Forbidden
    # FileNotFoundException         404 Not Found
    # RumtimeException              500 Internal Server Error
    # @param [Object] host
    # @param [Object] port
    # @param [Object] method
    # @param [Object] path
    # @param [Object] op
    # @param [Object] params
    # @param [Object] payload
    # @param [Object] header
    def request(host, port, method, path, op=nil, params={}, payload=nil, header=nil)
      req = HTTPI::Request.new
      krb5 = nil

      HTTPI.log     = true      # disable logging
      HTTPI.log_level= :debug
      HTTPI.adapter = :net_http #  one of [:httpclient, :curb, :net_http]


      if @auth_type == :kerberos
        if @username and @pass_keytab
          krb5 = Krb5Auth::Krb5.new
          inited = false;
          begin
            inited = krb5.get_init_creds_password(@username, @pass_keytab)
          rescue
            inited = krb5.get_init_creds_keytab(@username, @pass_keytab)
          end
          if inited
            krb5.cache
            HTTPI.adapter = :curb
            req.auth.gssnegotiate
          end
        end
      end
      # puts %x{klist}
      req.open_timeout = @open_timeout if @open_timeout
      req.read_timeout = @read_timeout if @read_timeout
      request_path = if op
                       build_path(path, op, params)
                     else
                       path
                     end
      req.url = URI::HTTP.build({:host => host, :port => port}) + request_path
      req.headers = header.nil? ? {} : header        #  MUST BE ASSIGN {} if nil BY zixian.shen
      req.body =  payload.nil? ? {} : payload        #  MUST BE ASSIGN {} if nil BY zixian.shen
      # puts ">>> req.url="+req.url.to_s
      # puts ">>> req.headers="+req.headers.to_s
      # puts ">>> req.body="+req.body.to_s

      res = HTTPI.request( method, req )
#      res = conn.send_request(method, request_path, payload, header)

      #puts res.code, res.code.class
      #puts res.headers, res.headers.class
      #puts res.body, res.body.class
      #puts res.headers['Content-Type'].include?('application/json')

      #case res
      #when Net::HTTPSuccess
      #  res
      #when Net::HTTPRedirection
      #  res
      if HTTPI::Response::SuccessfulResponseCodes.include?(res.code)
        krb5.destroy if not krb5.nil?
        res
      elsif REDIRECTED_CODE.include?(res.code)
        krb5.destroy if not krb5.nil?
        res
      else
        message = if res.body and not res.body.empty?
                    res.body.gsub(/\n/, '')
                  else
                    'Response body is empty...'
                  end
        case res.code
        when 400
          raise WebHDFS::ClientError, message
        when 401
          raise WebHDFS::SecurityError, message
        when 403
          raise WebHDFS::IOError, message
        when 404
          raise WebHDFS::FileNotFoundError, message
        when 500
          raise WebHDFS::ServerError, message
        else
          raise WebHDFS::RequestFailedError, "response code:#{res.code}, message:#{message}"
        end
      end
    end
  end
end
