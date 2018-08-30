polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details')
    // message: '',
    // actions: {
    //     submitData: function () {
    //         let self = this;
    //         this.sendIntegrationMessage({data: 'block.data.details.incidents'}).then(
    //             function (response) {
    //                 self.set('message', "Success!");
    //             }).catch(function (err) {
    //                 self.set('message', "ERROR!");
    //         });
    //     }
    // }
});
