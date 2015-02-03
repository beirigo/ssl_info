require "ssl_info/version"

# Heavily inspired by "http://findingscience.com/ruby/ssl/2013/01/13/reading-an-ssl-cert-in-ruby.html"

module SSLInfo

  Certificate = Struct.new(:valid_on, :valid_until, :issuer)

  def self.read(url)
    cert = download_cert(url)
    issuer = read_issuer(cert)
    Certificate.new(cert.not_before, cert.not_after, issuer)
  end

  private

  def self.download_cert(url)
    tcp_client = TCPSocket.new(url, 443)
    ssl_client = OpenSSL::SSL::SSLSocket.new(tcp_client)
    ssl_client.connect
    certificate = OpenSSL::X509::Certificate.new(ssl_client.peer_cert)
    ssl_client.sysclose
    tcp_client.close
    certificate
  end

  def self.read_issuer(cert)
    certprops = OpenSSL::X509::Name.new(cert.issuer).to_a
    certprops.select { |name, data, type| name == "O" }.first[1]
  end

end
