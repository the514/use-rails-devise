class User < ActiveRecord::Base
  belongs_to :role
  before_create :set_default_role
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable, :confirmable, :authentication_keys => [:login]

  attr_accessor :login

  validates :username,
    # 验证用户名不能为空
    presence:{
      message: "请填写用户名!"
    },
    # 验证用户名唯一(不区分大小写)
    :uniqueness => {
    :case_sensitive => false
  }

  validate :validate_username

  def validate_username
    if User.where(email: username).exists?
      errors.add(:username, :invalid)
    end
  end

  def login=(login)
    @login = login
  end

  def login
    # 使用用户名或邮件登录
    @login || self.username || self.email
  end

  def self.find_for_database_authentication(warden_conditions)
    conditions = warden_conditions.dup
    if login = conditions.delete(:login)
      # 不区分大小写
      where(conditions.to_hash).where(["lower(username) = :value OR lower(email) = :value", { :value => login.downcase }]).first
    elsif conditions.has_key?(:username) || conditions.has_key?(:email)
      where(conditions.to_hash).first
    end
    
  end

  private
  def set_default_role
    self.role ||= Role.find_by_name('registered')
  end

end

