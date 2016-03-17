class CreateTerms < ActiveRecord::Migration
  def change
    create_table :terms do |t|
      t.string :name, null: false
      t.datetime :start_at
      t.datetime :end_at
      t.timestamps null: false
    end
  end
end
