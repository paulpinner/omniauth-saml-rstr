require 'omniauth'

module OmniAuth
  module Strategies
    class SAML_RSTR
      include OmniAuth::Strategy

      class InvalidResponseException < Exception; end
      class NameIDMissingOrNil < Exception; end

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
          @attributes = response.attributes
          @audience = response.audience
          @issuer = response.issuer

          raise InvalidResponseException unless response.valid?
          raise NameIDMissingOrNil, "@name_id nil:\t#{@name_id.nil?}\n@name_id empty:\t#{@name_id.empty?}" if [@name_id.nil?, @name_id.empty?].any?
          return fail!(:invalid_ticket, OmniAuth::Error.new('Invalid SAML_RSTR Ticket')) if @name_id.nil? || @name_id.empty? || !response.valid?
          super
        rescue ArgumentError => e
          log :info, "#{e.message}"
          fail!(:invalid_ticket, OmniAuth::Error.new("Invalid SAML_RSTR Response \n #{e.backtrace}"))
        rescue InvalidResponseException => e
          log :info, "#{e.message}"
          log :info, "#{e.backtrace}"
          fail!(:invalid_response)
        rescue NameIDMissingOrNil => e
          log :info, "#{e.message}"
          log :info, "#{response.security_token_content.inspect}"
          log :info, "Available Data #{response.response_params}"
          fail!(:missing_data)
        end
      end

      uid { @name_id }

      info do
        {
          :name  => @name_id,
          :issuer => @issuer,
        }
      end

      extra { { :raw_info => @attributes, :audience => @audience} }

    end
  end
end

# OmniAuth.config.add_camelization 'saml', 'SAML'
OmniAuth.config.add_camelization 'saml_rstr', 'SAML_RSTR'