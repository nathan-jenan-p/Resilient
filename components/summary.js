'use strict';

polarity.export = PolarityComponent.extend({

details: Ember.computed.alias('block.data.details.body'),

otherData: Ember.computed('details', function(){
    let data = Ember.A();
    this.get('details.results').forEach(function(item){
        data.push(item.type_id);
        data.push(item.inc_name);
        data.push(item.score);
    });

    return data;
})


});
