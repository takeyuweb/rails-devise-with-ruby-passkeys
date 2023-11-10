class Passkeys::RequestOptionsController < ApplicationController
  include Warden::WebAuthn::StrategyHelpers
  include Warden::WebAuthn::AuthenticationInitiationHelpers

  # See https://github.com/cedarcode/webauthn-ruby#webauthncredentialoptions_for_getoptions
  # See https://github.com/ruby-passkeys/warden-webauthn/blob/main/lib/warden/webauthn/authentication_initiation_helpers.rb
  def create
    user_params = params.require(:user).permit(:email)
    user = User.find_by!(email: user_params[:email])

    request_options = WebAuthn::Credential.options_for_get(
      allow: user.passkeys.pluck(:external_id)
    )

    store_challenge_in_session(options_for_authentication: request_options)

    render json: request_options
  end
end
