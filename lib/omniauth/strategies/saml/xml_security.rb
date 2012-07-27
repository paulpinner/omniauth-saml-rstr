# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights responseerved
# Portions Copyrighted 2007 Todd W Saxton.

require 'rubygems'
require "rexml/document"
require "rexml/xpath"
require "openssl"
require "xmlcanonicalizer"
require "digest/sha1"
require "nokogiri"

module OmniAuth
  module Strategies
    class SAML

      module XMLSecurity

        class SecurityTokenResponseContent

          attr_accessor :name_identifier, :xml, :name_identifier_test, :x509_cert, :conditions_not_on_or_after, :conditions_before

          def initialize(response)
            puts "SecurityTokenResponseContent : response = " + response
            self.xml = Nokogiri::XML::Document.parse(response).remove_namespaces!()
          end

          def x509_cert
            @xml.css("X509Certificate").text
          end

          def conditions_before
            if !conditions.nil?
              conditions.attribute("NotBefore").value
            end
          end

          def conditions_not_on_or_after
            if !conditions.nil?
              conditions.attribute("NotOnOrAfter").value
            end
          end

          def name_identifier
            @xml.css("NameIdentifier").text
          end

          def validate(idp_cert_fingerprint, idp_cert=null, soft=true )
            if idp_cert
              decoded_cert_text = Base64.decode64(idp_cert)
            else
              decoded_cert_text = Base64.decode64(self.x509_cert)
            end
            certificate = OpenSSL::X509::Certificate.new(cert_text)
            fingerprint = Digest::SHA1.hexdigest(cert.to_der)
            if !fingerprint == idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/,"").downcase
               raise OmniAuth::Strategies::SAML::ValidationError.new("Key validation error")
            end
            return true
          end


          private

          def conditions
            @xml.css("Conditions")
          end

          end

      end

    end
  end
end
