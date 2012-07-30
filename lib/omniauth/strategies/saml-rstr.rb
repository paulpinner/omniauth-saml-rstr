require 'omniauth'

module OmniAuth
  module Strategies
    class SAML_RSTR
      include OmniAuth::Strategy

      autoload :AuthRequest,      'omniauth/strategies/saml-rstr/auth_request'
      autoload :AuthResponse,     'omniauth/strategies/saml-rstr/auth_response'
      autoload :ValidationError,  'omniauth/strategies/saml-rstr/validation_error'
      autoload :XMLSecurity,      'omniauth/strategies/saml-rstr/xml_security'

      option :name_identifier_format, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

      def request_phase
        request = OmniAuth::Strategies::SAML_RSTR::AuthRequest.new
        req = request.create(options)
        redirect(req)
      end

      def callback_phase

        begin
          response = OmniAuth::Strategies::SAML_RSTR::AuthResponse.new(request.params['wresult'])

          response.settings = options

          @name_id  = response.name_id

          puts "response = " + response.inspect
          puts "name id = " + @name_id

          @attributes = response.attributes

          return fail!(:invalid_ticket, OmniAuth::Error.new('Invalid SAML_RSTR Ticket')) if @name_id.nil? || @name_id.empty? || !response.valid?
          super
        rescue ArgumentError => e   
          fail!(:invalid_ticket, OmniAuth::Error.new('Invalid SAML_RSTR Response'))
        end
      end

      uid { @name_id }

      info do
        {
          :name  => @name_id
        }
      end

      extra { { :raw_info => @attributes } }

    end
  end
end

# OmniAuth.config.add_camelization 'saml', 'SAML'
OmniAuth.config.add_camelization 'saml_rstr', 'SAML_RSTR'