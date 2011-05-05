require 'rubygems'
require 'sinatra'
require 'openssl'
require 'haml'

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

  %p= message

  %form{:action => "/upload", :method => "post", :enctype => "multipart/form-data"}
    Upload a CA certificate file:
    %input{:type => "file",:name => "file"}
    %br
    %input{:type => "submit",:value => "upload"}

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

  post '/upload' do
    if file = params[:file]
      if tmpfile = file[:tempfile]
        begin
          uploaded = tmpfile.read
          cert = OpenSSL::X509::Certificate.new(uploaded)
          if hash = spki_sha1_hash(cert.to_der)
            message = "Uploaded certificate: #{cert.subject}<br/>\n" +
              "Public key fingerprint for Chrome HSTS preloading:<br/>\n" +
              " => " + hash
          end
        rescue Exception => e
          message = e.inspect
        end
      else
        message = 'Uploading failure'
      end
    end
    session[:message] = message
    redirect '/'
  end

  get '/' do
    message = session[:message]
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
end

run SPKIHashApp.new
