  # Be sure to restart your server when you modify this file.
  unless Rails.env.production?
    case Rails::VERSION::MAJOR
    when 5
    # ActiveSupport::Reloader.to_prepare do
        # reloader.execute <=他のファイルが更新されても実行するならこちら
        # reloader.execute_if_updated (Rails5)
    #   ApplicationController.renderer.defaults.merge!(
    #     http_host: 'example.org',
    #     https: false
    #   )
    # end
    when 4
    #   reloader = ActiveSupport::FileUpdateChecker.new(['path_to_file']) do
    #     # do_something
    #   end
    #   Rails.application.reloaders << reloader
    #   ActionDispatch::Reloader.to_prepare do
    #     reloader.execute_if_updated
    #   end
    end
  end

