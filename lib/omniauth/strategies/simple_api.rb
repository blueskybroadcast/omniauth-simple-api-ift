require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class SimpleApi < OmniAuth::Strategies::OAuth2

      option :client_options, {
        site: 'https://api.simple-api.com:443',
        authorize_url: '/auth/vendor',
        authenticate_url: '/api/remote_login/user/login',
        user_info_url: '/api/remote_login/sso/retriever',
        auth_token: 'N0VCOUIxRjctRjY1OS00MEFBLUJBNTgtODc5QTVGMkJDN0Qw'
        # auth_token: 'MUST BE SET'
      }

      uid { '1234' }

      name {'simple_api'}

      info do
        {
          first_name: raw_info['first_name'],
          last_name: raw_info['last_name'],
          email: raw_info['email']
        }
      end

      extra do
        { :raw_info => raw_info }
      end

      def creds
        self.access_token
      end

      def request_phase
        puts "!!!!!!!!!!!!!! IN REQUEST PHASE !!!!!!!!!!!!!!!!!!"
        slug = session['omniauth.params']['origin'].gsub(/\//,"")
        puts "!!!!!!!!!!!!!! SLUG = #{slug} !!!!!!!!!!!!!!!!!!"
        auth_request = authorize(callback_url, slug)
        puts "!!!!!!!!!!!!!! AUTH REQ = #{auth_request} !!!!!!!!!!!!!!!!!!"
        redirect auth_request["data"]["authUrl"]
        # redirect client.auth_code.authorize_url({:return_url => callback_url + "?slug=#{slug}"})
      end

      def callback_phase
        if member_id
          response = authenticate

          if response.success?
            response_body = JSON.parse(response.body)
            self.access_token = {
              :token => response_body['token']
            }

            self.session_id = response_body['sessid']
            self.session_name = response_body['session_name']

            self.env['omniauth.auth'] = auth_hash
            self.env['omniauth.origin'] = '/' + request.params['slug']
            call_app!
          else
            fail!(:invalid_credentials)
          end
        else
          fail!(:invalid_credentials)
        end
      end

      def auth_hash
        hash = AuthHash.new(:provider => name, :uid => uid)
        hash.info = info
        hash.credentials = creds
        hash
      end

      def raw_info
        @raw_info ||= get_user_info(access_token[:token], member_id)
      end

      private

      def get_user_info(token, member_id)
        response = Typhoeus.post(user_info_url,
          body: { uid: member_id },
          headers: {'Cookie' => "#{session_name}=#{session_id}", 'X-CSRF-Token' => token})

        if response.success?
          JSON.parse(response.body)
        else
          nil
        end
      end

      def auth_token
        options.client_options.auth_token
      end

      def authorize(callback, slug)
        callback_url = "#{callback}?slug=#{slug}"

        response = Typhoeus.get("https://api.simple-api.com:443/auth/vendor?return=#{callback_url}",
          headers: { Authorization: "Basic #{auth_token}" }
        )

        if response.success?
          JSON.parse(response.body)
        else
          nil
        end
      end
    end
  end
end
