require 'jose'
require 'json'
require 'base64'

module CognitoRuby
  class CognitoJWTVerifier

    # Setup unique Amazon AWS settings

    # Set ENV['AWS_ISS'] = https://cognito-idp.{region}.amazonaws.com/{userPoolId}

    # Raw keys retrieved from 
    # https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json
    # Set ENV['AWS_COGNITO_KEYS']

    class << self

      KEYS = JSON.parse(ENV['AWS_COGNITO_KEYS'])['keys'].freeze
      TOKEN_USE_CLAIM = 'id'

      def validate_and_decrypt(token)
        claims = nil 
        begin 
          # Retrieve the key id (kid) from the token headers.
          kid = get_kid_from(token)
          # Find the key with kid in keys.
          key_index = find_key_index(kid)
          raise "Unable to locate key." if key_index.nil? # Probably want to raise errors.
          
          # Construct the public key.
          public_key = JOSE::JWK.from_map(KEYS[key_index].to_hash)
          # Get the last 2 sections of the token, payload and signature.
          encoded_signature = token.split('.')[2]
          # Decode the signature.
          decoded_signature = Base64.decode64(encoded_signature)

          # decoded_token returns [<pass/fail boolean>, payload, signature].
          decoded_token = verify_and_decode_token(public_key, token)
          raise "Token signature invalid." if !decoded_token[0] # Probably want to raise errors.

          # Since we have passed verification we can use the unverfied claims.
          claims = JSON.parse(decoded_token[1])

          # Verify the token expiration.
          raise "Token expired." if !expired_token?(claims)
          # Check the iss.
          raise "Invalid ISS claim." if invalid_iss?(claims)
          # Check the token_use_claim.
          raise "Invalid token use claim." if invalid_token_use_claim?(claims)
        rescue Exception => e
          error = e.message.to_s
          claims = nil
        ensure 
          # How would I make this a struct? or 'wrap' it?
          # Struct.new(claims: claims, errors: error) does not work.
          # throws TypeError: no implicit conversion of Hash into String
          #return Struct.new(claims: claims, errors: error)
          return {claims: claims, errors: error} 
        end
      end

      private
        def get_kid_from(token)
          headers = JOSE::JWT.peek_protected(token)
          headers['kid']
        end

        def find_key_index(kid)
          key_index = nil
          KEYS.each_with_index do |key, i|
            key_index = i if key['kid'] == kid
          end
          key_index
        end

        def verify_and_decode_token(public_key, token)
          decoded_token = JOSE::JWS.verify(public_key, token)
        end

        def expired_token?(claims)
          Time.now() > Time.at(claims['exp'])
        end

        def invalid_iss?(claims)
          !claims['iss'] = ENV["AWS_ISS"]
        end

        def invalid_token_use_claim?(claims)
          !claims['token_use'] = TOKEN_USE_CLAIM
        end
    end # singleton
  end # class
end # module