# OmniAuth SAML-RSTR

![](https://raw.githubusercontent.com/wiki/thinkthroughmath/omniauth-saml-rstr/saml-rstr.png)

An XML & SAML strategy for OmniAuth integration with ADFS 2.0.

https://github.com/highgroove/omniauth-saml-rstr

## Requirements

* [OmniAuth](http://www.omniauth.org/) 1.0+
* nokogiri 1.5
* SAML 1.1
* Ruby 1.9.2

## Usage

Use the SAML strategy as a middleware in your application:

```ruby
require 'omniauth'
use OmniAuth::Strategies::SAML_RSTR,
  :assertion_consumer_service_url => "consumer_service_url",
  :issuer                         => "issuer",
  :idp_sso_target_url             => "idp_sso_target_url",
  :idp_cert                       => "-----BEGIN CERTIFICATE-----\n...-----END CERTIFICATE-----",
  :idp_cert_fingerprint           => "E7:91:B2:E1:...",
  :name_identifier_format         => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
```

or in your Rails application:

in `Gemfile`:

```ruby
gem 'omniauth-saml-rstr'
```

and in `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :saml_rstr,
    :assertion_consumer_service_url => "consumer_service_url",
    :issuer                         => "rails-application",
    :idp_sso_target_url             => "idp_sso_target_url",
    :idp_cert                       => "-----BEGIN CERTIFICATE-----\n...-----END CERTIFICATE-----",
    :idp_cert_fingerprint           => "E7:91:B2:E1:...",
    :name_identifier_format         => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
end
```

## Options

* `:assertion_consumer_service_url` - The URL at which the SAML assertion should be
  received. With OmniAuth this is typically `http://example.com/auth/callback`.
  **Required**.

* `:issuer` - The name of your application. Some identity providers might need this
  to establish the identity of the service provider requesting the login. **Required**.

* `:idp_sso_target_url` - The URL to which the authentication request should be sent.
  This would be on the identity provider. **Required**.

* `:idp_cert` - The identity provider's certificate in PEM format. Takes precedence
  over the fingerprint option below. This option or `:idp_cert_fingerprint` must
  be present.

* `:idp_cert_fingerprint` - The SHA256 fingerprint of the certificate, e.g.
  "90:CC:16:F0:8D:...". This is provided from the identity provider when setting up
  the relationship. This option or `:idp_cert` must be present.

* `:name_identifier_format` - Describes the format of the username required by this
  application. If you need the email address, use "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".
  See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf section 8.3 for
  other options. Note that the identity provider might not support all options.
  Optional.

## Authors

Authored by Josh Skeen [www.joshskeen.com]. 
Based on the work of Raecoo Cao, Todd W Saxton, Ryan Wilcox, Rajiv Aaron Manglani, and Steven Anderson.

<!-- Maintained by [Rajiv Aaron Manglani](http://www.rajivmanglani.com/). -->

## License

Copyright (c) 2012 Think Through Learning Inc.
Developed at Highgroove Studios [http://www.highgroove.com]

Copyright (c) 2011-2012 [Practically Green, Inc.](http://www.practicallygreen.com/).  
All rights reserved. Released under the MIT license.

Portions Copyright (c) 2007 Sun Microsystems Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
