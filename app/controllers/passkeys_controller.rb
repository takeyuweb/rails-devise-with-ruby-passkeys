class PasskeysController < ApplicationController
  def index
    @passkeys = current_user.passkeys
  end

  def create
    # TODO
  end

  def destroy
    @passkey = current_user.passkeys.find(params[:id])
    @passkey.destroy
    redirect_to passkeys_path
  end
end
