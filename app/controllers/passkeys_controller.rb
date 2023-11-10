class PasskeysController < ApplicationController
  include Warden::WebAuthn::RegistrationHelpers
  before_action :verify_passkey_registration_challenge, only: :create

  def index
    @passkeys = current_user.passkeys
  end

  def create
    current_user.passkeys.create!(
      label: passkey_params[:label],
      external_id: @webauthn_credential.id,
      public_key: @webauthn_credential.public_key,
      sign_count: @webauthn_credential.sign_count,
      last_used_at: Time.current
    )

    redirect_to passkeys_path
  end

  def destroy
    @passkey = current_user.passkeys.find(params[:id])
    @passkey.destroy
    redirect_to passkeys_path
  end

  private

  def passkey_params
    params.require(:passkey).permit(:label, :credential)
  end

  # Warden::WebAuthn::RegistrationHelpers#raw_credential をオーバーライドする
  def raw_credential
    passkey_params[:credential]
  end

  # Warden::WebAuthn::RegistrationHelpers#verify_passkey_registration_challenge を使ってチャレンジを検証する
  def verify_passkey_registration_challenge
    @webauthn_credential = verify_registration(relying_party: WebAuthn.configuration.relying_party)
  rescue ::WebAuthn::Error => e
    error_key = Warden::WebAuthn::ErrorKeyFinder.webauthn_error_key(exception: e)
    render json: { message: find_message(error_key) }, status: :bad_request
  end
end
