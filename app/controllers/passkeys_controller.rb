class PasskeysController < ApplicationController
  include Passkeyable

  def index
    @passkeys = current_user.passkeys
  end

  def create
    passkey_params = params.require(:passkey).permit(:label, :credential)
    parsed_credential = JSON.parse(passkey_params[:credential]) rescue nil
    webauthn_credential = relying_party.verify_registration(
      parsed_credential, stored_registration_challenge, user_verification: true
    )

    current_user.passkeys.create!(
      label: passkey_params[:label],
      external_id: webauthn_credential.id,
      public_key: webauthn_credential.public_key,
      sign_count: webauthn_credential.sign_count,
      last_used_at: Time.current
    )

    redirect_to passkeys_path
  end

  def destroy
    @passkey = current_user.passkeys.find(params[:id])
    @passkey.destroy
    redirect_to passkeys_path
  end
end
