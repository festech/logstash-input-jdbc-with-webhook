# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/plugin_mixins/jdbc"
require "stud/interval"
require "logstash-input-http_jars"

java_import "io.netty.handler.codec.http.HttpUtil"

# Using this input you can receive single or multiline events over http(s).
# Applications can send a HTTP POST request with a body to the endpoint started by this
# input and Logstash will convert it into an event for subsequent processing. Users
# can pass plain text, JSON, or any formatted data and use a corresponding codec with this
# input. For Content-Type `application/json` the `json` codec is used, but for all other
# data formats, `plain` codec is used.
#
# This input can also be used to receive webhook requests to integrate with other services
# and applications. By taking advantage of the vast plugin ecosystem available in Logstash
# you can trigger actionable events right from your application.
#
# ==== Security
# This plugin supports standard HTTP basic authentication headers to identify the requester.
# You can pass in an username, password combination while sending data to this input
#
# You can also setup SSL and send data securely over https, with an option of validating
# the client's certificate. Currently, the certificate setup is through
# https://docs.oracle.com/cd/E19509-01/820-3503/ggfen/index.html[Java Keystore
# format]
#
class LogStash::Inputs::JdbcHttp < LogStash::Inputs::Base
  include LogStash::PluginMixins::Jdbc

  config_name "jdbchttp"

  # Codec used to decode the incoming data.
  # This codec will be used as a fall-back if the content-type
  # is not found in the "additional_codecs" hash
  default :codec, "plain"

  ##### JDBC variables
  # Statement to execute
  #
  # To use parameters, use named parameter syntax.
  # For example:
  #
  # [source, ruby]
  # -----------------------------------------------
  # "SELECT * FROM MYTABLE WHERE id = :target_id"
  # -----------------------------------------------
  #
  # here, ":target_id" is a named parameter. You can configure named parameters
  # with the `parameters` setting.
  config :statement, :validate => :string

  # Path of file containing statement to execute
  config :statement_filepath, :validate => :path

  # Hash of query parameter, for example `{ "target_id" => "321" }`
  config :parameters, :validate => :hash, :default => {}

  # Schedule of when to periodically run statement, in Cron format
  # for example: "* * * * *" (execute query every minute, on the minute)
  #
  # There is no schedule by default. If no schedule is given, then the statement is run
  # exactly once.
  #config :schedule, :validate => :string

  # Use an incremental column value rather than a timestamp
  config :use_column_value, :validate => :boolean, :default => false

  # If tracking column value rather than timestamp, the column whose value is to be tracked
  config :tracking_column, :validate => :string

  # Type of tracking column. Currently only "numeric" and "timestamp"
  config :tracking_column_type, :validate => ['numeric', 'timestamp'], :default => 'numeric'

  # Whether the previous run state should be preserved
  config :clean_run, :validate => :boolean, :default => false

  # Whether to save state or not in last_run_metadata_path
  config :record_last_run, :validate => :boolean, :default => true

  # Whether to force the lowercasing of identifier fields
  config :lowercase_column_names, :validate => :boolean, :default => true

  # The character encoding of all columns, leave empty if the columns are already properly UTF-8
  # encoded. Specific columns charsets using :columns_charset can override this setting.
  config :charset, :validate => :string

  # The character encoding for specific columns. This option will override the `:charset` option
  # for the specified columns.
  config :columns_charset, :validate => :hash, :default => {}

  # Path to file with last run time
  config :last_run_metadata_path, :validate => :string, :default => "#{ENV['HOME']}/.logstash_jdbc_last_run"

  ##### HTTP variables
  # The host or ip to bind
  config :host, :validate => :string, :default => "0.0.0.0"

  # The TCP port to bind to
  config :port, :validate => :number, :default => 8887

  # Username for basic authorization
  config :user, :validate => :string, :required => false

  # Password for basic authorization
  config :password, :validate => :password, :required => false

  # Apply specific codecs for specific content types.
  # The default codec will be applied only after this list is checked
  # and no codec for the request's content-type is found
  config :additional_codecs, :validate => :hash, :default => { "application/json" => "json" }

  # specify a custom set of response headers
  config :response_headers, :validate => :hash, :default => { 'Content-Type' => 'text/plain' }

  # target field for the client host of the http request
  config :remote_host_target_field, :validate => :string, :default => "host"

  # target field for the client host of the http request
  config :request_headers_target_field, :validate => :string, :default => "headers"

  config :threads, :validate => :number, :required => false, :default => ::LogStash::Config::CpuCoreStrategy.maximum

  config :max_pending_requests, :validate => :number, :required => false, :default => 200

  config :max_content_length, :validate => :number, :required => false, :default => 100 * 1024 * 1024

  public
  def register
    #JDBC
    @logger = self.logger
    prepare_jdbc_connection

    if @use_column_value
      # Raise an error if @use_column_value is true, but no @tracking_column is set
      if @tracking_column.nil?
        raise(LogStash::ConfigurationError, "Must set :tracking_column if :use_column_value is true.")
      end
    end

    @value_tracker = LogStash::PluginMixins::ValueTracking.build_last_value_tracker(self)

    @enable_encoding = !@charset.nil? || !@columns_charset.empty?

    unless @statement.nil? ^ @statement_filepath.nil?
      raise(LogStash::ConfigurationError, "Must set either :statement or :statement_filepath. Only one may be set at a time.")
    end

    @statement = File.read(@statement_filepath) if @statement_filepath

    if (@jdbc_password_filepath and @jdbc_password)
      raise(LogStash::ConfigurationError, "Only one of :jdbc_password, :jdbc_password_filepath may be set at a time.")
    end

    @jdbc_password = LogStash::Util::Password.new(File.read(@jdbc_password_filepath).strip) if @jdbc_password_filepath

    if enable_encoding?
      encodings = @columns_charset.values
      encodings << @charset if @charset

      @converters = encodings.each_with_object({}) do |encoding, converters|
        converter = LogStash::Util::Charset.new(encoding)
        converter.logger = self.logger
        converters[encoding] = converter
      end
    end

    #HTTP
    @codecs = Hash.new

    @additional_codecs.each do |content_type, codec|
      @codecs[content_type] = LogStash::Plugin.lookup("codec", codec).new
    end

    require "logstash/inputs/http/message_handler"
    message_handler = MessageHandler.new(self, @codec, @codecs, @auth_token)
    @http_server = create_http_server(message_handler)
  end # def register

  def run(queue)
    @queue = queue
    @logger.info("Starting http input listener", :address => "#{@host}:#{@port}", :ssl => "#{@ssl}")
    @http_server.run()
  end

  def stop
    close_jdbc_connection
    @http_server.close() rescue nil
  end

  def close
    @http_server.close() rescue nil
  end

  def decode_body(headers, remote_address, body, default_codec, additional_codecs)
    content_type = headers.fetch("content_type", "")
    codec = additional_codecs.fetch(HttpUtil.getMimeType(content_type), default_codec)
    codec.decode(body) { |event| push_decoded_event(headers, remote_address, event) }
    codec.flush { |event| push_decoded_event(headers, remote_address, event) }
    true
  rescue => e
    @logger.error(
      "unable to process event.",
      :message => e.message,
      :class => e.class.name,
      :backtrace => e.backtrace
    )
    false
  end

  def push_decoded_event(headers, remote_address, event)
    event.set(@request_headers_target_field, headers)
    event.set(@remote_host_target_field, remote_address)
    decorate(event)
    //add event_details from web event
    execute_query(queue, event_details)
  end

  def create_http_server(message_handler)
    org.logstash.plugins.inputs.http.NettyHttpServer.new(
      @host, @port, message_handler, build_ssl_params(), @threads, @max_pending_requests, @max_content_length)
  end

  private

  def execute_query(queue, event_details)
      # update default parameters
      @parameters['sql_last_value'] = @value_tracker.value
      execute_statement(@statement, @parameters) do |row|
        if enable_encoding?
          ## do the necessary conversions to string elements
          row = Hash[row.map { |k, v| [k.to_s, convert(k, v)] }]
        end
        event = LogStash::Event.new(row)
        decorate(event)
        queue << event
      end
      @value_tracker.write
  end

  def enable_encoding?
    @enable_encoding
  end

  # make sure the encoding is uniform over fields
  def convert(column_name, value)
    return value unless value.is_a?(String)
    column_charset = @columns_charset[column_name]
    if column_charset
      converter = @converters[column_charset]
      converter.convert(value)
    elsif @charset
      converter = @converters[@charset]
      converter.convert(value)
    else
      value
    end
  end

end # class LogStash::Inputs::JdbcHttp
