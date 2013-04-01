require 'authorized_keys'

Puppet::Type.type(:ssh_authorized_key_ng).provide :parsed do
  desc "Parse and generate authorized_keys files for SSH (multiple users support)."

  mk_resource_methods

  def initialize(type)
    super(type)

    @parsed_files = nil
    @files_to_update = []
  end

  def files
    @parsed_files ||= self.parse_files
  end

  def create_key
    key = AuthorizedKeys::Key.new()
    key.options = resource[:options].include?(:absent) ? [] : resource[:options]
    key.type = resource[:type]
    key.content = resource[:key]
    key.comment = resource[:name]
    return key
  end

  def parse_files
    files = {}

    for t in resource[:target] do
      f = AuthorizedKeys::File.new(t)

      begin
        files[t] = f.keys
      rescue Errno::ENOENT => e
        self.check_structure(t)
      end
    end

    files
  end

  def create
    Puppet.debug 'create()'
    Puppet.debug resource[:target]

    key = self.create_key

    for t in resource[:target] do
      f = AuthorizedKeys::File.new(t)

      begin
        keys = f.keys
      rescue Errno::ENOENT => e
        Puppet.warning "#{t} does not exist"
      end

      # check all key in this authorizes_files file
      for k in keys
        if k.content == resource[:key]
          if k.to_s == key
            break # everything is the same
          else
            # Needs updating
            f.remove(k)
            break
          end
        end
      end

      f.add(key)

    end

  end

  def destroy
    Puppet.debug 'destroy'

    key = self.create_key

    for t in resource[:target] do
      f = AuthorizedKeys::File.new(t)

      begin
        keys = f.keys
      rescue Errno::ENOENT => e
        next
      end

      # check all key in this authorizes_files file
      for k in keys
        if k.content == resource[:key]
          f.remove(k)
        end
      end
    end
  end

  def key
    return resource[:key]
  end

  def type
    return resource[:type]
  end

  def user
    return resource[:user]
  end

  def target
    return resource[:target]
  end

  def options
    return resource[:options]
  end

  def exists?
    Puppet.debug resource[:ensure]

    if resource[:ensure] == :present
      return self.all_exist
    else
      return !self.all_absent
    end
  end

  def all_exist
    Puppet.debug 'all_exist?'

    key = self.create_key
    for t in resource[:target] do
      return false if not files[t]
      return false if files[t].length == 0
      return false if not files[t].find_all { |k| k.to_s == key.to_s }
    end

    Puppet.debug 'all_exist? returns true'
    return true
  end

  def all_absent
    Puppet.debug 'all_absent?'

    key = self.create_key
    for t in resource[:target] do
      next if not files[t]
      next if files[t].length == 0
      return false if files[t].find_all { |k| k.to_s == key.to_s }
    end

    Puppet.debug 'all_absent? returns true'
    return true
  end

  def dir_perm
    0700
  end

  def file_perm
    0600
  end

  def check_structure(target)
    index = resource[:target].index(target)
    user = resource[:user][index]
    Puppet::Util::SUIDManager.asuser(user) do
      unless File.exist?(dir = File.dirname(target))
        Dir.mkdir(dir, dir_perm)
      end

      unless File.exist?(target)
        File.open(target, "w") {}
        File.chmod(file_perm, target)
      end

    end
  end

end
