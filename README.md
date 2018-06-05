## Amazon Web Services (AWS) Cognito validator and decrypter

This project serves as an example class for a backend AWS JSON Web Token (JWT) validation and decryption tool for Ruby.  

## Example

```
CognitoJWTVerification.new(token).validate_and_decrypt
```

## Motivation

When using AWS Cognito for user authentication, Cognito can respond with a JWT.  This JWT contains a header, payload and signature with pertinent data.  Before utilizing any of this data, it should be validated as authentic.

The process is  explained here in a pseudo-code format: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html 

AWS Lambda can can serve to validate and decrpty token, and https://github.com/awslabs/aws-support-tools/tree/master/Cognito/decode-verify-jwt provides an explanation of the validation and decryption process and examples in both Python and Node.js.

There are no additional examples.

If you chose to pass the JWT back to your Ruby or Ruby on Rails based server, you need to validate the token's authenticity before trusting any of its claims. as explained in the AWS documentation.

Currently this is an example class which goes through each of the validation tokens

## Installation

Clone repo and require class.

Setup:
Get and store your public keys for Cognito from:
https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json

## TODO 

I would like to turn this into a Gem for Ruby / ROR, however, this enough for one night.
Goodnight moon.

## Contributors

github: @IAmWhil

Feel free to fork this!

## License

Copyright 2018 Whil Piavis

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.