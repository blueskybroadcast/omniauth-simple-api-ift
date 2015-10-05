require 'omniauth-oauth2'
require 'builder'

module OmniAuth
  module Strategies
    class SimpleApiIft < OmniAuth::Strategies::OAuth2

      option :client_options, {
        site: 'https://api.simple-api.com:443',
        authorize_url: '/auth/vendor',
        customer_info_url: '/auth/customer',
        member_info_url: '/directapi',
        auth_token: 'MUST BE SET'
      }

      option :name, 'simple_api_ift'

      uid { raw_customer_info['customerId'] }

      info do
        {
          first_name: raw_member_info.xpath('//FirstName', force_encoding: 'UTF-16').children.text,
          last_name: raw_member_info.xpath('//LastName', force_encoding: 'UTF-16').children.text,
          email: raw_member_info.xpath('//Email', force_encoding: 'UTF-16').children.text,
          member_status: raw_member_info.xpath('//MemberStatus', force_encoding: 'UTF-16').children.text
        }
      end

      extra do
        { :raw_info => raw_member_info }
      end

      def creds
        self.access_token
      end

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//,"")

        auth_request = authorize(callback_url, slug)
        redirect auth_request["data"]["authUrl"]
      end

      def callback_phase
        if customer_token

          self.access_token = {
            :token => customer_token
          }

          self.env['omniauth.auth'] = auth_hash
          self.env['omniauth.origin'] = '/' + request.params['slug']
          call_app!
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

      def raw_customer_info
        @raw_customer_info ||= get_customer_info(customer_token)
      end

      def raw_member_info
        @raw_member_info ||= get_member_info
      end

      def customer_id
        raw_customer_info['customerId'].split('|').first
      end

      def sub_customer_id
        raw_customer_info['customerId'].split('|').last
      end

      private

      def auth_token
        options.client_options.auth_token
      end

      def auth_url
        "#{options.client_options.site}#{options.client_options.authorize_url}"
      end

      def authorize(callback, slug)
        callback_url = "#{callback}?slug=#{slug}"

        response = Typhoeus.get(auth_url + "?return=#{callback_url}",
          headers: { Authorization: "Basic #{auth_token}" }
        )
        log_request_details(__callee__, response)

        if response.success?
          JSON.parse(response.body)
        else
          nil
        end
      end

      def build_member_xml
        xml_builder = ::Builder::XmlMarkup.new
        xml_builder.UserDefined_LMSCustomerInput {
          xml_builder.MasterCustomerId customer_id
          xml_builder.SubCustomerId sub_customer_id
        }
        xml_builder.target!
      end

      def customer_token
        request.params['ct']
      end

      def get_member_info
        response = Typhoeus.post(member_info_url,
          headers: { Authorization: "Basic #{auth_token}" },
          body: {
            httpMethod: 'POST',
            serviceSet: 'Data Services',
            path: '/UserDefined_GetLMSCustomer',
            body: build_member_xml
          }
        )
        log_request_details(__callee__, response)

        if response.success?
          member_data = JSON.parse(response.body)['data']['data']
          doc = Nokogiri::XML(member_data)
        else
          nil
        end
      end

      def get_customer_info(customer_token)
        response = Typhoeus.get(customer_info_url + "?token=#{customer_token}",
          headers: { Authorization: "Basic #{auth_token}" })
        log_request_details(__callee__, response)

        if response.success?
          Rails.logger.debug JSON.parse(response.body)
          JSON.parse(response.body)['data']
        else
          nil
        end
      end

      def customer_info_url
        "#{options.client_options.site}#{options.client_options.customer_info_url}"
      end

      def log_request_details(callee, response)
        Rails.logger.info "%% #{options.name} #{callee.to_s}:: "\
          "date: #{response.headers['date']}; "\
          "server: #{response.headers['server']}; "\
          "request-id: #{response.headers['request-id']}; "\
          "response-time: #{response.headers['response-time']}; %%"
      end

      def member_info_url
        "#{options.client_options.site}#{options.client_options.member_info_url}"
      end
    end
  end
end
