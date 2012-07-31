require 'spec_helper'

RSpec::Matchers.define :fail_with do |message|
  match do |actual|
    actual.redirect? && actual.location.include?("/auth/failure?message")
  end
end

def post_xml(xml=:rstr_response)
  post "/auth/saml_rstr/callback", {'wresult' => load_xml(xml)}
end

describe OmniAuth::Strategies::SAML_RSTR, :type => :strategy do
  include OmniAuth::Test::StrategyTestCase
  let(:invalid_ticket){ OmniAuth::Error.new }
  let(:auth_hash){ last_request.env['omniauth.auth'] }
  let(:saml_options) do
    {
      :assertion_consumer_service_url => "http://localhost:3000/auth/saml_rstr/callback",
      :issuer                         => "https://saml.issuer.url/issuers/29490",
      :idp_sso_target_url             => "https://idp.sso.target_url/signon/29490",
      :idp_cert_fingerprint           => "76:C5:6A:64:E0:D8:81:44:11:24:F2:9C:1B:41:56:27:6E:3B:FB:8C",
      :name_identifier_format         => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    }
  end
  let(:strategy) { [OmniAuth::Strategies::SAML_RSTR, saml_options] }

  describe 'GET /auth/saml_rstr' do
    before do
      get '/auth/saml_rstr'
    end

    it 'should get authentication page' do
      last_response.should be_redirect
    end
  end

  describe 'POST /auth/saml_rstr/callback' do
    subject { last_response }
    let(:xml) { :rstr_response }
    before :each do
      Time.stub(:now).and_return(Time.new(2012, 3, 8, 16, 25, 00, 0))
    end
    
    context "when the response is valid" do
      puts "when the response is valid"
      before :each do
        post_xml
      end

      it "should set the uid to the nameID in the SAML response" do
        auth_hash['uid'].should == 'highgroove@thinkthroughmath.com'
      end

      it "should set the raw info to all attributes" do
        auth_hash['extra']['raw_info'].to_hash.should == {
          'userEmailID' => 'highgroove@thinkthroughmath.com'
        }
      end
    end

    context "when there is no wresult parameter" do
      before :each do
        post '/auth/saml_rstr/callback'
      end
      it { should fail_with(:invalid_ticket) }
    end

    context "when there is no name id in the XML" do
      before :each do
        post_xml :rstr_no_name
      end

      it { should fail_with(:invalid_ticket) }
    end

    context "when the fingerprint is invalid" do
      before :each do
        saml_options[:idp_cert_fingerprint] = "E6:87:89:FB:F2:5F:CD:B0:31:32:7E:05:44:84:53:B1:EC:4E:3F:gg"
        post_xml
      end
      it { should fail_with(:invalid_ticket) }
      # it {should raise_error(OmniAuth::Strategies::SAML_RSTR::ValidationError, "Fingerprint validation error")}
    end

    context "when the digest is invalid" do
      before :each do
        post_xml :digest_mismatch
      end

      it { should fail_with(:invalid_ticket) }
    end

    context "when the signature is invalid" do
      before :each do
        post_xml :rstr_invalid_signature
        puts "invalid signature"
      end
      it { should fail_with(:invalid_ticket) }
    end

    context "when the time is before the NotBefore date" do
      before :each do
        Time.stub(:now).and_return(Time.new(2000, 3, 8, 16, 25, 00, 0))
        post_xml
      end

      it { should fail_with(:invalid_ticket) }
    end

    context "when the time is after the NotOnOrAfter date" do
      before :each do
        Time.stub(:now).and_return(Time.new(3000, 3, 8, 16, 25, 00, 0))
        post_xml
      end

      it { should fail_with(:invalid_ticket) }
    end


  end
end
