class User < ApplicationRecord
	validates :username, presence: true, uniqueness: true 
	validates :password_digest, presence: true, uniqueness: true 
	validates :password, length: {minimum: 6}, allow_nil: true 

	before_validation :ensure_session_token 

	def self.find_by_credentials(username, password)
		user = User.find_by(username: username)
		if user && user.is_password?(password)
			return user 
		else 
			return nil 
		end
	end

	def is_password?(password)
		bcrypt_obj = BCrypt::Password.new(self.password_digest)
		bcrypt_obj.is_password?(password)
	end

	def generate_session_token 
		token = SecureRandom::urlsafe_base64
		while User.exists?(session_token: token)
			token = SecureRandom::urlsafe_base64
		end
		token
	end
end
