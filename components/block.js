polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  // message: '',
  actions: {
    submitData: function (id) {
      let note = this.get('note');
      let self = this;

      self.set('message', 'Pending...');
      self.set('disabled', true);

      this.sendIntegrationMessage({ data: { inc_id: id, note: note } }).then(
        function () {
          self.set('note', null);
          self.set('message', "Success!");
        }).catch(function (err) {
          console.error(err);
          self.set('message', "Error adding note");
        }).finally(function () {
          self.set('disabled', false);
        });
    }
  }
});
