require "cognito_ruby/version"
require 'jose'
require 'json'
require 'base64'

module CognitoRuby
  class CognitoJWTVerifier

    # Setup unique Amazon AWS settings
    REGION = '' # AWS Region. Eg. us-west-2
    ISS = "" # https://cognito-idp.{region}.amazonaws.com/{userPoolId}
    TOKEN_USE_CLAIM = 'id'

    # Raw keys retrieved from 
    # https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json
    RAW_KEYS = ''

    def initialize(token)
      @token = token
      @keys = JSON.parse(RAW_KEYS)['keys']
    end

    def validate_and_decrypt()
      # Retrieve the key id (kid) from the token headers.
      kid = get_kid_from(@token)
      # Find the key with kid in keys.
      key_index = find_key_index(kid)
      return false if key_index.nil? # Probably want to raise errors.
      
      # Construct the public key.
      public_key = JOSE::JWK.from_map(@keys[key_index].to_hash)
      # Get the last 2 sections of the token, payload and signature.
      encoded_signature = @token.split('.')[2]
      # Decode the signature.
      decoded_signature = Base64.decode64(encoded_signature)

      # decoded_token returns [<pass/fail boolean>, payload, signature].
      decoded_token = verify_and_decode_token(public_key, @token)
      return false if !decoded_token[0] # Probably want to raise errors.

      # Since we have passed verification we can use the unverfied claims.
      claims = JSON.parse(decoded_token[1])

      # Verify the token expiration.
      return false if expired_token?(claims)
      # Check the iss.
      return false if invalid_iss?(claims)
      # Check the token_use_claim.
      return false if invalid_token_use_claim?(claims)

      claims
    end

    private
      def get_kid_from(token)
        headers = JOSE::JWT.peek_protected(@token)
        headers['kid']
      end

      def find_key_index(kid)
        key_index = nil
        @keys.each_with_index do |key, i|
          key_index = i if key['kid'] == kid
        end
        key_index
      end

      def verify_and_decode_token(public_key, token)
        decoded_token = JOSE::JWS.verify(public_key, @token)
      end

      def expired_token?(claims)
        Time.now() > Time.at(claims['exp'])
      end

      def invalid_iss?(claims)
        !claims['iss'] = ISS
      end

      def invalid_token_use_claim?(claims)
        !claims['token_use'] = TOKEN_USE_CLAIM
      end
      
  end # class
end # module