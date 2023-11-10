class Passkeys::RequestOptionsController < ApplicationController
  include Passkeyable

  def create
    user_params = params.require(:user).permit(:email)
    user = User.find_by!(email: user_params[:email])

    request_options = WebAuthn::Credential.options_for_get(
      allow: user.passkeys.pluck(:external_id)
    )

    store_authentication_challenge(request_options)

    render json: request_options
  end
end
