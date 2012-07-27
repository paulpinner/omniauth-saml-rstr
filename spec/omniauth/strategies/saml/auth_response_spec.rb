require 'spec_helper'

describe OmniAuth::Strategies::SAML::AuthResponse do
  let(:xml) { :rstr_response }
  subject { described_class.new(load_xml(xml)) }

  describe :initialize do
    context "when the response is nil" do
      it "should raise an exception" do
        expect { described_class.new(nil) }.to raise_error ArgumentError
      end
    end
  end
# 2012-07-25T21:16:34.271Z
 describe :session_expires_at do
    it "should return the SessionNotOnOrAfter as a Ruby date" do
      subject.session_expires_at.to_i.should == Time.new(2012, 07, 25, 21, 16, 34, 0).to_i
    end
  end

  describe :name_id do
    it "should load the name id from the assertion" do
      subject.name_id.should == 'highgroove@thinkthroughmath.com'
    end
  end

  describe :valid? do
    it_should_behave_like 'a validating method', true
  end

  describe :validate! do
    it_should_behave_like 'a validating method', false
  end



end
