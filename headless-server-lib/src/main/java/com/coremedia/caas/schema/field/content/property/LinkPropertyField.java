package com.coremedia.caas.schema.field.content.property;

import com.coremedia.caas.schema.Types;
import com.coremedia.caas.schema.datafetcher.content.property.LinkPropertyDataFetcher;
import com.coremedia.caas.schema.field.common.AbstractField;

import com.google.common.collect.ImmutableList;
import graphql.schema.GraphQLFieldDefinition;

import java.util.Collection;

import static graphql.schema.GraphQLFieldDefinition.newFieldDefinition;

public class LinkPropertyField extends AbstractField {

  public LinkPropertyField() {
    super(false, true);
  }


  @Override
  public Collection<GraphQLFieldDefinition> build() {
    return ImmutableList.of(newFieldDefinition()
            .name(getName())
            .type(Types.getType(getTypeName(), isNonNull()))
            .dataFetcherFactory(decorate(new LinkPropertyDataFetcher(getSourceName(), getFallbackSourceNames(), Types.getBaseTypeName(getTypeName()))))
            .build());
  }
}
