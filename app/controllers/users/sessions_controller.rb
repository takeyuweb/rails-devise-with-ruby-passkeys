# frozen_string_literal: true

class Users::SessionsController < Devise::SessionsController
  # before_action :configure_sign_in_params, only: [:create]

  # GET /resource/sign_in
  # def new
  #   super
  # end

  # POST /resource/sign_in
  # def create
  #   super
  # end
  def create
    if authrized_passkey.present?
      self.resource = authrized_passkey.user
      set_flash_message!(:notice, :signed_in)
      sign_in(resource_name, resource)
      yield resource if block_given?
      respond_with resource, location: after_sign_in_path_for(resource)
    else
      super
    end
  end

  # DELETE /resource/sign_out
  # def destroy
  #   super
  # end

  # protected

  # If you have extra params to permit, append them to the sanitizer.
  # def configure_sign_in_params
  #   devise_parameter_sanitizer.permit(:sign_in, keys: [:attribute])
  # end

  def authrized_passkey
    return @authrized_passkey if defined?(@authrized_passkey)

    passkey_params = params.require(:passkey).permit(:credential)
    parsed_credential = JSON.parse(passkey_params[:credential]) rescue nil
    return @authrized_passkey = nil unless parsed_credential

    authentication_challenge = session[:current_webauthn_authentication_challenge]
    x, passkey = WebAuthn.configuration.relying_party.verify_authentication(
      parsed_credential,
      authentication_challenge,
      user_verification: true
    ) do |webauthn_credential|
      user = User.find_by(email: params[:user][:email])
      user.passkeys&.find_by!(external_id: webauthn_credential.id)
    end

    @authrized_passkey = passkey
  end
end
