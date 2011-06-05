require 'rubygems'
require 'sinatra'
require 'openssl'
require 'haml'
require 'uri'
require 'httpclient'
require 'logger'

class SPKIHashApp < Sinatra::Application
  enable :sessions

  INDEX = <<__EOS__
!!! XHTML 1.0 Transitional
%html{:xmlns => "http://www.w3.org/1999/xhtml"}
%head
  %meta{'http-equiv' => 'Content-Type', :content => 'text/html'}
  %title
    Public key fingerprint calculator for Chrome
%body
  %h1
    Public key fingerprint calculator for Chrome

  %p
    It's just a proof-of-concept. Do not trust it and calculate it by yourself for actual use.

  %p= message

  %br

  %form{:action => "/upload", :method => "post", :enctype => "multipart/form-data"}
    Upload a CA certificate file:
    %br
    %input{:type => "file", :name => "file"}
    %input{:type => "submit", :value => "upload"}

  %br
  %br

  %form{:action => "/fetch", :method => "post"}
    Fetch a certificate chain of given SSL server:
    %br
    %input{:type => "text", :value => "https://", :name => "url"}
    %input{:type => "submit", :value => "fetch"}

  %br

  %p
    %a{:href => 'http://www.imperialviolet.org/2011/05/04/pinning.html'}
      What's the Public key fingerprint for Chrome?

  %p
    Source:
    %a{:href => 'https://github.com/nahi/spkihash'}https://github.com/nahi/spkihash

  %p
    Author:
    %a{:href => 'https://twitter.com/nahi'}@nahi
__EOS__

  helpers do
    include Rack::Utils
    alias_method :h, :escape_html
  end

  post '/upload' do
    if file = params[:file]
      if tmpfile = file[:tempfile]
        begin
          uploaded = tmpfile.read
          log("Uploaded #{uploaded.bytesize} bytes")
          cert = OpenSSL::X509::Certificate.new(uploaded)
          hash = spki_sha1_hash(cert.to_der)
          log_hash(cert, hash)
          message = dump_cert_message(cert, hash)
        rescue Exception => e
          log(e)
          message = e.message
        end
      else
        message = 'Uploading failure'
      end
    end
    session[:message] = message
    redirect '/'
  end

  post '/fetch' do
    if url = params[:url]
      if !url.empty? && url != 'https://'
        log("Fetch: #{url}")
        begin
          uri = urify(url)
          message = fetch_certs(uri).map { |cert|
            hash = spki_sha1_hash(cert.to_der)
            log_hash(cert, hash)
            dump_cert_message(cert, hash)
          }.join("\n\n")
        rescue Exception => e
          log(e)
          message = e.message
          if message.nil? || message.empty?
            message = e.class.name
          end
          message = "Connection failed: #{message}"
        end
        message = "Connecting to #{uri.to_s}...\n\n" + message
      end
    end
    session[:message] = message
    redirect '/'
  end

  get '/' do
    message = session[:message].to_s.split(/\n/).map { |line| h(line) }.join("<br/>\n")
    Haml::Engine.new(INDEX).render(self, :message => message)
  end

private

  # find first SEQUENCE of SEQUENCE in TBSCertificate
  # tag == 16 is a SEQUENCE chunk
  def spki_sha1_hash(cert)
    spki = OpenSSL::ASN1.decode(cert).value[0].find { |e|
      e.tag == 16 && e.value[0].tag == 16
    }
    return unless spki
    ["sha1", [OpenSSL::Digest::SHA1.digest(spki.to_der)].pack('m*').chomp].join("/")
  end

  def cert_md5_hash(cert)
    OpenSSL::Digest::MD5.hexdigest(cert.to_der)
  end

  # set path to '/'
  def urify(url)
    url = url.to_s.downcase
    if %r(^https://) !~ url
      url = 'https://' + url
    end
    URI.parse(url) + '/'
  end

  def fetch_certs(uri)
    certs = []
    c = HTTPClient.new
    c.ssl_config.verify_callback = proc { |ok, ctx|
      unless certs.find { |cert| cert.to_der == ctx.current_cert.to_der }
        certs << ctx.current_cert
      end
      true
    }
    c.get(uri)
    certs
  end

  def dump_cert_message(cert, hash)
    [
      "Fetched certificate of #{cert.subject}",
      "Certificate fingerprint(MD5): #{cert_md5_hash(cert)}",
      "SPKI fingerprint: #{hash}"
    ].join("\n")
  end

  def log_hash(cert, hash)
    log([hash, cert_md5_hash(cert), cert.subject].join("\t"))
  end

  def log(msg)
    Logger.new(STDERR).info(msg)
  end
end

run SPKIHashApp.new
